use crate::filter::StoreContents;
use crate::scan::{InputPkgs, VulnixRes};
use crate::source::AllPackages;
use crate::Roundup;

use anyhow::{bail, ensure, Context, Result};
use colored::*;
use git2::Repository;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use smol_str::SmolStr;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use thiserror::Error;

/// NixOS release to scan. Note that the git rev/branch may have a different name than the release
/// name we publish.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Branch {
    /// NixOS release name to publish in tickets
    pub name: SmolStr,
    /// git parseable revspec, usually a branch name
    pub rev: SmolStr,
}

impl Branch {
    pub fn new(name: &str) -> Self {
        Self {
            name: SmolStr::from(name),
            rev: SmolStr::from(name),
        }
    }

    fn checkout(&self, repo: &Path) -> Result<()> {
        info!(
            "Checking out {} @ {}",
            self.name.green().bold(),
            self.rev[0..11].yellow()
        );
        let status = Command::new("git")
            .args(&["checkout", "-q", &self.rev])
            .current_dir(repo)
            .status()
            .context("Cannot execute git")?;
        ensure!(
            status.success(),
            "Failed to check out git revision {}",
            self.rev.to_string()
        );
        Ok(())
    }

    /// File path of the vulnix.json result file
    fn vulnix_json<P: AsRef<Path>>(&self, iterdir: P) -> PathBuf {
        iterdir.as_ref().join(format!("vulnix.{}.json", self.name))
    }
}

#[derive(Debug, Error)]
pub enum BranchErr {
    #[error("Invalid branch specification {spec}")]
    Invalid { spec: String },
}

lazy_static! {
    static ref BRANCHSPEC: Regex = Regex::new(r"^([^/=[:space:]]+)(=(\S+))?$").unwrap();
}

impl FromStr for Branch {
    type Err = BranchErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match BRANCHSPEC.captures(s) {
            Some(cap) => {
                let name = &cap[1];
                match cap.get(3) {
                    Some(rev) => Ok(Branch {
                        name: name.into(),
                        rev: rev.as_str().into(),
                    }),
                    None => Ok(Branch::new(name)),
                }
            }
            None => Err(BranchErr::Invalid { spec: s.to_owned() }),
        }
    }
}

impl fmt::Display for Branch {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.name.as_str())
    }
}

/// Intermediary: arranges vulnix scan results by branch. Will be consolidated later.
pub type ScanByBranch = HashMap<Branch, Vec<VulnixRes>>;

fn resolve_rev(rev: &str, repo: &Repository) -> Result<String> {
    Ok(repo.revparse_single(rev)?.id().to_string())
}

/// Saves JSON result dump for later consuption with `-R`/[`Branches::load`]
fn snapshot<P: AsRef<Path>>(scan_res: &[VulnixRes], dest: P) -> Result<()> {
    Ok(serde_json::to_writer_pretty(
        BufWriter::new(File::create(dest)?),
        &scan_res,
    )?)
}

/// Enumerates inividual checkouts of the same repo which should be scanned in turn.
#[derive(Default, Clone)]
pub struct Branches {
    specs: Vec<Branch>,
    repo: Option<PathBuf>,
}

impl Branches {
    /// List of branches without git repository. Used when loading previous scan results
    /// from directory.
    pub fn init(specs: &[Branch]) -> Result<Self> {
        let b = Self {
            specs: specs.to_owned(),
            ..Default::default()
        };
        for (idx, elem) in specs.iter().enumerate() {
            if specs.iter().skip(idx + 1).any(|s| s.name == elem.name) {
                bail!("Duplicate branch {}", elem.name.as_str());
            }
        }
        Ok(b)
    }

    /// List of branches with associated git repository. Used when scanning from source.
    pub fn with_repo(specs: &[Branch], repo: &Path) -> Result<Self> {
        let mut bs = Branches {
            repo: Some(repo.to_owned()),
            ..Branches::init(specs)?
        };
        let repo = Repository::open(repo).context("Cannot open repository")?;
        for mut b in bs.specs.iter_mut() {
            b.rev = SmolStr::from(resolve_rev(b.rev.as_str(), &repo)?);
        }
        Ok(bs)
    }

    /// Reads previous scan results from a directory
    pub fn load(&self, dir: &Path) -> Result<ScanByBranch> {
        info!(
            "Loading scan results from {}",
            dir.to_string_lossy().green()
        );
        let mut sbb = ScanByBranch::new();
        for branch in self.iter() {
            let v = branch.vulnix_json(&dir);
            sbb.insert(
                branch.clone(),
                File::open(&v)
                    .and_then(|f| Ok(serde_json::from_reader(BufReader::new(f))?))
                    .with_context(|| format!("Error while loading vulnix results from {:?}", v))?,
            );
        }
        Ok(sbb)
    }

    /// Checks out all specified branches in turn, instantiates the release derivation and invokes
    /// vulnix on it. Figures out maintainers for affected packages.
    /// A snapshot of vulnix' output is saved for subsequent `-R` invocations.
    /// Returns [`ScanByBranch`] struct which is fed into [`ticket_list`].
    pub fn scan(&self, dir: &Path, r_opt: &Roundup) -> Result<ScanByBranch> {
        let repo = self
            .repo
            .as_ref()
            .expect("Bug: attempted to scan unspecified repository");
        fs::create_dir_all(&dir).ok();
        let filter = match r_opt.filter {
            Some(ref dir) => Some(StoreContents::from_dir(dir)?),
            None => None,
        };
        let mut sbb = ScanByBranch::new();
        for branch in self.iter() {
            branch.checkout(repo)?;
            let mut all_pkgs =
                AllPackages::query(repo).context("nix-build packages.json failed")?;
            if let Some(stores_filter) = filter.as_ref() {
                all_pkgs.retain(|pi| stores_filter.is_installed(pi))
            }
            let patches = all_pkgs.discover_patches(repo)?;
            let pkgs = InputPkgs::new(&all_pkgs, patches);
            if r_opt.keep {
                let savedpkgs = dir.join(&format!("input.{}.json", branch.name));
                pkgs.save(&savedpkgs)
                    .with_context(|| format!("Failed to write input pkgs to {:?}", savedpkgs))?;
            }
            let pkgs = pkgs.to_file()?;
            let scan_res = VulnixRes::run_vulnix(&branch.name, &pkgs, r_opt)
                .with_context(|| {
                    format!(
                        "Scan failed - keeping derivation list for reference in {:?}",
                        pkgs.keep().expect("failed to persist tmp file").1
                    )
                })?
                .into_iter()
                .map(|res| res.add_maintainers(&all_pkgs.packages))
                .collect::<Vec<_>>();
            if scan_res.is_empty() {
                warn!(
                    "vulnix reported no issues for {}. Please double check. Re-run with `-R`?",
                    branch.name.yellow()
                );
                continue;
            }
            let snapfile = branch.vulnix_json(&dir);
            snapshot(&scan_res, &snapfile)
                .with_context(|| format!("Cannot write vulnix results json to {:?}", snapfile))?;
            sbb.insert(branch.clone(), scan_res);
        }
        Ok(sbb)
    }
}

impl Deref for Branches {
    type Target = [Branch];

    fn deref(&self) -> &Self::Target {
        &self.specs
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::br;

    use git2::Repository;
    use libflate::gzip;
    use std::error::Error;
    use std::fs::File;
    use tar::Archive;
    use tempfile::TempDir;

    #[test]
    fn correct_branchspecs() {
        assert_eq!(
            Branch::from_str("nixos-18.09").unwrap(),
            Branch {
                name: "nixos-18.09".into(),
                rev: "nixos-18.09".into()
            }
        );
        assert_eq!(
            Branch::from_str("nixos-18.09=55f4cd48").unwrap(),
            Branch {
                name: "nixos-18.09".into(),
                rev: "55f4cd48".into()
            }
        );
        assert_eq!(
            Branch::from_str("nixos-18.09=origin/release-18.09").unwrap(),
            Branch {
                name: "nixos-18.09".into(),
                rev: "origin/release-18.09".into()
            }
        );
    }

    #[test]
    fn branchspec_invalid_chars() {
        assert!(Branch::from_str("nixos 18.09").is_err());
        assert!(Branch::from_str("origin/nixos-18.09").is_err());
    }

    #[test]
    fn branchspec_empty() {
        assert!(Branch::from_str("nixos=").is_err());
        assert!(Branch::from_str("=abcdefg").is_err());
    }

    #[test]
    fn no_duplicate_branch_names() {
        assert!(Branches::init(&[br("a"), br("b")]).is_ok());
        assert!(Branches::init(&[br("a"), br("b"), br("a")]).is_err());
    }

    #[test]
    fn resolve_branches() -> Result<(), Box<dyn Error>> {
        let tmp = TempDir::new()?;
        let tarball = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/repo.tar.gz");
        Archive::new(gzip::Decoder::new(File::open(tarball)?)?).unpack(&tmp)?;
        let repo = Repository::open(&tmp.path().join("repo"))?;
        assert_eq!(
            "117a41dff30a62f2e4ef68c7e237ed497150b6dd",
            resolve_rev("117a41d", &repo)?
        );
        assert_eq!(
            "8dfec1442bf901fbfc09572ae0ea58d5ce8b4462",
            resolve_rev("master", &repo)?
        );
        assert_eq!(
            "12fe4b957c99f41b0885021599b445ac4a02623a",
            resolve_rev("b1", &repo)?
        );
        Ok(())
    }
}
