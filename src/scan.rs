use crate::advisory::Advisory;
use crate::nix::{self, Ping};
use crate::package::{Attr, Maintainer, Package};
use crate::Roundup;

use anyhow::{bail, ensure, Context, Result};
use colored::*;
use git2::Repository;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use smallstr::SmallString;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::BufWriter;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use subprocess::{Exec, ExitStatus::*};
use thiserror::Error;

pub type ScoreMap = HashMap<Advisory, f32>;

/// `vulnix` scan result item.
///
/// Nearly all of the fields are present in vulnix' JSON output. The only exception is the
/// `maintainers` vec which will be filled in later.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VulnixRes {
    #[serde(rename = "name")]
    pub pkg: Package,
    pub pname: SmallString<[u8; 20]>,
    pub version: SmallString<[u8; 20]>,
    pub derivation: String,
    pub affected_by: Vec<Advisory>,
    #[serde(default)]
    pub whitelisted: Vec<SmallString<[u8; 20]>>,
    #[serde(default)]
    pub cvssv3_basescore: ScoreMap,
    #[serde(default)]
    pub maintainers: Vec<Maintainer>,
}

impl VulnixRes {
    #[allow(unused)]
    pub fn new(pkg: Package, affected_by: Vec<Advisory>) -> Self {
        let pname = pkg.pname().into();
        let version = pkg.version().into();
        Self {
            pkg,
            pname,
            version,
            affected_by,
            ..Self::default()
        }
    }

    fn augment(mut self, maint: &HashMap<Attr, Ping>) -> Self {
        for ping in maint.values() {
            if ping.name == self.pkg {
                self.maintainers.extend(ping.maintainers.clone());
            }
        }
        self
    }
}

/// NixOS release to scan. Note that the git rev/branch may have a different name than the release
/// name we publish.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Branch {
    /// NixOS release name to publish in tickets
    pub name: SmallString<[u8; 20]>,
    /// git parseable revspec, usually a branch name
    pub rev: SmallString<[u8; 20]>,
}

impl Branch {
    pub fn new(name: &str) -> Self {
        Self {
            name: SmallString::from_str(name),
            rev: SmallString::from_str(name),
        }
    }

    fn checkout(&self, repo: &Path) -> Result<()> {
        info!(
            "Checking out {} @ {}",
            self.name.green().bold(),
            self.rev[0..11].yellow()
        );
        let status = Exec::cmd("git")
            .args(&["checkout", "-q", &self.rev])
            .cwd(repo)
            .join()
            .context("Cannot execute git")?;
        ensure!(
            status.success(),
            "Failed to check out git revision {}",
            self.rev.to_string()
        );
        Ok(())
    }

    /// Invokes `vulnix` on a derivation
    ///
    /// vulnix' output is saved to a JSON file iff parsing passed.
    fn run_vulnix<P: AsRef<Path>>(&self, drvlist: P, opt: &Roundup) -> Result<Vec<VulnixRes>> {
        info!("Scanning derivations from {}", drvlist.as_ref().display());
        let full_wl = opt.whitelist_dir.join(format!("{}.toml", self.name));
        let cmd = Exec::cmd(&opt.vulnix)
            .args(&["-j", "-R", "-w"])
            .arg(&full_wl)
            .arg("-W")
            .arg(&full_wl)
            .arg("-f")
            .arg(drvlist.as_ref());
        debug!("{}", cmd.to_cmdline_lossy().purple());
        let c = cmd.capture().context("Failed to read stdout from vulnix")?;
        match c.exit_status {
            Exited(e) if e <= 2 => (),
            _ => bail!("vulnix failed with exit status {:?}", c.exit_status),
        }
        serde_json::from_slice(&c.stdout)
            .with_context(|| format!("Cannot parse vulnix JSON output: {:?}", &c.stdout))
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

fn postprocess(
    scan: Vec<VulnixRes>,
    maintainers: &HashMap<Attr, Ping>,
    out_json: &Path,
) -> Result<Vec<VulnixRes>> {
    // add maintainers for each scan result
    let scan = scan
        .into_iter()
        .map(|res| res.augment(maintainers))
        .collect();
    // save for future reference
    serde_json::to_writer(BufWriter::new(File::create(out_json)?), &scan)
        .with_context(|| format!("Failed to write vulnix output to {:?}", out_json))?;
    Ok(scan)
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
            b.rev = SmallString::from(resolve_rev(b.rev.as_str(), &repo)?);
        }
        Ok(bs)
    }

    /// Reads previous scan results from a directory
    pub fn load(&self, opt: &Roundup) -> Result<ScanByBranch> {
        info!(
            "Loading scan results from {}",
            opt.iterdir().to_string_lossy().green()
        );
        let mut sbb = ScanByBranch::new();
        for branch in self.iter() {
            let v = opt.vulnix_json(&branch.name);
            sbb.insert(
                branch.clone(),
                File::open(&v)
                    .and_then(|f| Ok(serde_json::from_reader(f)?))
                    .with_context(|| format!("Error while loading vulnix results from {:?}", v))?,
            );
        }
        Ok(sbb)
    }

    /// Checks out all specified branches in turn, instantiates the release derivation and invokes
    /// vulnix on it. Figures out maintainers for affected packages.
    pub fn scan(&self, opt: &Roundup) -> Result<ScanByBranch> {
        let repo = self
            .repo
            .as_ref()
            .expect("Bug: attempted to scan unspecified repository");
        let dir = opt.iterdir();
        fs::create_dir_all(&dir).ok();
        let mut sbb = ScanByBranch::new();
        for branch in self.iter() {
            branch.checkout(repo)?;
            let attrs = nix::all_derivations(repo)?;
            nix::ensure_drvs_exist(repo, &attrs)?;
            let drvlist = attrs.dump_drvlist()?;
            let scan_res = branch.run_vulnix(&drvlist, opt).with_context(|| {
                format!(
                    "Scan failed - retaining derivation list in {:?}",
                    drvlist.keep().unwrap()
                )
            })?;
            let maintainers = nix::collect_maintainers(
                repo,
                attrs
                    .iter()
                    .filter(|(_, drv)| scan_res.iter().any(|res| res.pkg == drv.name))
                    .map(|(k, _v)| k),
            )
            .context("Error while querying package maintainers")?;
            debug!("Collected maintainers: {:?}", maintainers);
            sbb.insert(
                branch.clone(),
                postprocess(scan_res, &maintainers, &opt.vulnix_json(&branch.name))?,
            );
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

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::{br, create_branches, pkg};

    use libflate::gzip;
    use std::error::Error;
    use std::fs::{create_dir, read_to_string};
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

    /// Little shell script which unconditionally writes the contents of
    /// fixtures/iterations/1/vulnix.nixos-18.09.json to stdout
    fn fake_vulnix() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake_vulnix")
    }

    /// Standard `Opt` struct for testing purposes
    fn opt() -> Roundup {
        Roundup {
            vulnix: fake_vulnix(),
            basedir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/iterations"),
            iteration: 1,
            ..Roundup::default()
        }
    }

    #[test]
    fn load_json() {
        let opt = opt();
        let branches = create_branches(&["nixos-18.03", "nixos-18.09", "nixos-unstable"]);
        let sbb = branches.load(&opt).unwrap();
        // check only hash lengths; we compare exact strings in the ticket tests
        assert_eq!(sbb.len(), 3);
        assert_eq!(sbb[&br("nixos-18.03")].len(), 2);
        assert_eq!(sbb[&br("nixos-18.09")].len(), 4);
        assert_eq!(sbb[&br("nixos-unstable")].len(), 3);
    }

    #[test]
    fn vulnix() -> Result<(), Box<dyn Error>> {
        let mut opt = opt();
        let td = TempDir::new()?;
        opt.basedir = td.path().to_path_buf();
        create_dir(opt.basedir.join("1"))?;
        let orig_json = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/iterations/1/vulnix.nixos-18.09.json");
        let exp: Vec<VulnixRes> = serde_json::from_str(&read_to_string(&orig_json)?)?;
        let res = br("nixos-18.09").run_vulnix(PathBuf::from("result"), &opt)?;
        assert_eq!(res, exp);
        Ok(())
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

    #[test]
    fn postprocess_scan() -> Result<()> {
        let scan = serde_json::from_str(include_str!(
            "../fixtures/iterations/1/vulnix.nixos-unstable.json"
        ))?;
        let maint = serde_json::from_str(include_str!("../fixtures/maintainers.nix.json"))?;
        let t = TempDir::new()?;
        let tp = t.path();
        eprintln!("{:?}", tp);
        serde_json::to_writer(File::create(tp.join("before.json"))?, &scan).unwrap();
        let scan = postprocess(scan, &maint, &tp.join("postprocess.json"))?;
        // verify that postprocess.json contains all the data
        assert_eq!(
            scan,
            serde_json::from_reader::<_, Vec<VulnixRes>>(File::open(tp.join("postprocess.json"))?)?
        );
        assert_eq!(&scan[1].pkg, "ncurses-6.1");
        assert_eq!(scan[1].maintainers, &["andir", "edolstra"]);
        assert_eq!(&scan[2].pkg, "binutils-2.30");
        assert_eq!(scan[2].maintainers, &["ericson2314"]);
        Ok(())
    }

    #[test]
    fn augment_maintainers() {
        let maint: HashMap<Attr, Ping> =
            serde_json::from_str(&include_str!("../fixtures/maintainers.nix.json")).unwrap();
        let res = VulnixRes::new(pkg("ncurses-6.1"), vec![]);
        assert_eq!(
            res.augment(&maint).maintainers,
            &[Maintainer::from("andir"), Maintainer::from("edolstra")]
        );
    }
}
