use crate::advisory::Advisory;
use crate::source::{AllPackages, Attr, Maintainer, NixEnvPkg, Package, Patches};
use crate::Roundup;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

type Str = smol_str::SmolStr;
pub type ScoreMap = HashMap<Advisory, f32>;

/// `vulnix` scan result item.
///
/// Nearly all of the fields are present in vulnix' JSON output. The only exception is the
/// `maintainers` vec which will be filled in later.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VulnixRes {
    #[serde(rename = "name")]
    pub pkg: Package,
    pub pname: Str,
    pub version: Str,
    pub affected_by: Vec<Advisory>,
    #[serde(default)]
    pub whitelisted: Vec<Str>,
    #[serde(default)]
    pub cvssv3_basescore: ScoreMap,
    #[serde(default)]
    pub maintainers: Vec<Maintainer>,
}

type PkgMap = HashMap<Attr, NixEnvPkg>;

impl VulnixRes {
    #[allow(dead_code)]
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

    /// Invokes `vulnix` over a JSON dump of all packages.
    pub fn run_vulnix<P: AsRef<Path>>(
        branch_name: &str,
        all_pkgs: P,
        r_opt: &Roundup,
    ) -> Result<Vec<Self>> {
        info!("Scanning derivations from {}", all_pkgs.as_ref().display());
        let full_wl = r_opt.whitelist_dir.join(format!("{}.toml", branch_name));
        let mut cmd = Command::new(&r_opt.vulnix);
        cmd.args(&["-j", "-R", "-w"])
            .arg(&full_wl)
            .arg("-W")
            .arg(&full_wl)
            .arg("-f")
            .arg(all_pkgs.as_ref());
        debug!("{:?}", cmd);
        let c = cmd.output().context("Failed to read stdout from vulnix")?;
        ensure!(
            c.status.code().unwrap_or(127) <= 2,
            "vulnix failed with {}: {}",
            c.status,
            String::from_utf8_lossy(&c.stdout)
        );
        serde_json::from_slice(&c.stdout).with_context(|| {
            format!(
                "Cannot parse vulnix JSON output: {} ({})",
                String::from_utf8_lossy(&c.stdout),
                String::from_utf8_lossy(&c.stderr),
            )
        })
    }

    /// Augments myself with maintainer contacts taken from pkginfo map.
    pub fn add_maintainers(mut self, pkgmap: &PkgMap) -> Self {
        for pi in pkgmap.values() {
            // unfortunately we don't have the attrname in vulnix' output, so we must search for
            // the package
            if self.pkg == pi.pkg {
                self.maintainers.extend_from_slice(&pi.meta.maintainers);
            }
        }
        self
    }
}

/// Information about a single package as expected in vulnix' JSON input
#[derive(Debug, Default, Serialize)]
struct InputPkg {
    name: Str,
    patches: Vec<String>,
    known_vulnerabilities: Vec<Str>,
}

/// JSON package representation suitable as input to vulnix
#[derive(Debug, Default, Serialize)]
pub struct InputPkgs(HashMap<Attr, InputPkg>);

impl InputPkgs {
    /// Takes packages.json and a dictionary of applied patches to get a complete set of packages
    /// indexed by attribute name.
    pub fn new(all: &AllPackages, mut patches: Patches) -> Self {
        let mut res = HashMap::with_capacity(all.packages.len());
        for (attr, pkginfo) in &all.packages {
            let pkg = InputPkg {
                name: pkginfo.pkg.clone(),
                patches: patches.remove(attr).unwrap_or_default(),
                known_vulnerabilities: pkginfo.meta.known_vulnerabilities.clone(),
            };
            res.insert(attr.clone(), pkg);
        }
        Self(res)
    }

    pub fn to_file(&self) -> Result<NamedTempFile> {
        let mut tf = tempfile::Builder::new().suffix(".json").tempfile()?;
        serde_json::to_writer(tf.as_file_mut(), &self.0)
            .with_context(|| format!("Failed to write vulnix packages.json to {:?}", tf.path()))?;
        Ok(tf)
    }

    /// Writes a nicely formatted copy of the input package list to `dst`.
    pub fn save<P: AsRef<Path>>(&self, dst: P) -> Result<()> {
        debug!("Saving input JSON as {:?}", dst.as_ref());
        let mut f = File::create(dst)?;
        serde_json::to_writer_pretty(&f, &self.0)?;
        writeln!(f, "")?;
        Ok(())
    }
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use crate::source::maintainer_contacts;
    use crate::tests::{br, create_branches};

    use std::error::Error;
    use std::fs::read_to_string;

    /// Standard `Opt` struct for testing purposes
    fn opt() -> Roundup {
        // Little shell script which unconditionally writes the contents of
        // fixtures/iterations/1/vulnix.nixos-18.09.json to stdout
        let fake_vulnix = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake_vulnix");
        Roundup {
            vulnix: fake_vulnix,
            iteration: 1,
            ..Roundup::default()
        }
    }

    #[test]
    fn load_json() {
        let branches = create_branches(&["nixos-18.03", "nixos-18.09", "nixos-unstable"]);
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/iterations/1");
        let sbb = branches.load(&dir).unwrap();
        // check only hash lengths; we compare exact strings in the ticket tests
        assert_eq!(sbb.len(), 3);
        assert_eq!(sbb[&br("nixos-18.03")].len(), 2);
        assert_eq!(sbb[&br("nixos-18.09")].len(), 4);
        assert_eq!(sbb[&br("nixos-unstable")].len(), 3);
    }

    #[test]
    fn vulnix() -> Result<(), Box<dyn Error>> {
        let orig_json = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/iterations/1/vulnix.nixos-18.09.json");
        let all = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/packages.json");
        let res = VulnixRes::run_vulnix("nixos-18.09", &all, &opt())?;
        let exp: Vec<VulnixRes> = serde_json::from_str(&read_to_string(&orig_json)?)?;
        assert_eq!(res, exp);
        Ok(())
    }

    #[test]
    fn should_add_maintainers() -> Result<()> {
        let all: AllPackages = serde_json::from_str(include_str!("../fixtures/packages.json"))?;
        let scan = serde_json::from_str::<Vec<VulnixRes>>(include_str!(
            "../fixtures/iterations/1/vulnix.nixos-unstable.json"
        ))?
        .into_iter()
        .map(|res| res.add_maintainers(&all.packages))
        .collect::<Vec<_>>();
        assert_eq!(&scan[1].pkg, "ncurses-6.1");
        assert_eq!(
            maintainer_contacts(&scan[1].maintainers),
            &["andir", "edolstra"]
        );
        assert_eq!(&scan[2].pkg, "binutils-2.30");
        assert_eq!(maintainer_contacts(&scan[2].maintainers), &["ericson2314"]);
        Ok(())
    }
}
