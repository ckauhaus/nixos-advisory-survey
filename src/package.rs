use anyhow::{bail, Result};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use smol_str::SmolStr;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::TempPath;
use thiserror::Error;

/// Nix package name. Must contain a dash followed by a version
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Package {
    pub name: SmolStr,
    v_idx: usize,
}

impl Package {
    #[allow(unused)]
    fn new<S: AsRef<str>>(pname: S, version: S) -> Self {
        let mut name = pname.as_ref().to_owned();
        name.push_str("-");
        name.push_str(version.as_ref());
        Self {
            name: SmolStr::from(name),
            v_idx: pname.as_ref().len() + 1,
        }
    }

    pub fn pname(&self) -> &str {
        &self.name[..self.v_idx - 1]
    }

    #[allow(unused)]
    pub fn version(&self) -> &str {
        &self.name[self.v_idx..]
    }

    pub fn as_str(&self) -> &str {
        self.name.as_str()
    }
}

impl fmt::Display for Package {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.name)
    }
}

impl Into<String> for Package {
    fn into(self) -> String {
        self.to_string()
    }
}

impl PartialEq<str> for Package {
    fn eq(&self, other: &str) -> bool {
        self.name.eq(other)
    }
}

lazy_static! {
    /// See parseDrvName in https://nixos.org/nix/manual/#ssec-builtins
    pub static ref VERSION_SPLIT: Regex = Regex::new(r"-[0-9]").unwrap();
}

#[derive(Debug, Error)]
pub enum PackageErr {
    #[error("Failed to find version in derivation name '{}'", name)]
    Version { name: String },
}

impl FromStr for Package {
    type Err = PackageErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(m) = VERSION_SPLIT.find(s) {
            Ok(Self {
                name: SmolStr::from(s),
                v_idx: m.start() + 1,
            })
        } else {
            Err(PackageErr::Version { name: s.to_owned() })
        }
    }
}

impl TryFrom<String> for Package {
    type Error = <Self as FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&s)
    }
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct Drv {
    pub name: Package,
    #[serde(rename = "drvPath")]
    pub path: PathBuf,
}

impl Drv {
    #[allow(unused)]
    pub fn new<D: AsRef<Path>>(name: &str, drv: D) -> Self {
        Self {
            name: name.parse().unwrap(),
            path: PathBuf::from(drv.as_ref()),
        }
    }
}

/// Nix attribute name. Can also be a dotted expression like pythonPackages.docutils
pub type Attr = SmolStr;

/// Maintainer Github handle
pub type Maintainer = SmolStr;

/// Eval'ed derivations by attribute name
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct DrvByAttr(HashMap<Attr, Drv>);

/// Package build architecture to consider
pub const ARCH: &str = "x86_64-linux";

impl DrvByAttr {
    /// Parse nix-instantiate --eval --json output.
    ///
    /// Note that this may contain some irregular entries which are filtered out. Considers only
    /// pkgs for `ARCH`.
    pub fn parse_instantiation<P: AsRef<Path>>(out_json: P) -> Result<Self> {
        debug!(
            "Parsing nix-instantiate JSON output in {}",
            out_json.as_ref().display()
        );
        // XXX serde_query?
        let json: Value = serde_json::from_reader(File::open(out_json.as_ref())?)?;
        // see fixtures/eval-release.json for expected file format
        if let Value::Object(map) = json {
            let mut by_attr = HashMap::with_capacity(map.len());
            for (attr, val) in map {
                if let Value::Object(pkg) = val {
                    for (arch, attrs) in pkg {
                        match (arch, attrs) {
                            (arch, obj @ Value::Object(_)) if arch == ARCH => {
                                if let Ok(eval) = serde_json::from_value::<Drv>(obj) {
                                    if VERSION_SPLIT.is_match(&eval.name.as_str()) {
                                        by_attr.insert(Attr::from(&attr), eval);
                                    }
                                }
                            }
                            _ => continue,
                        }
                    }
                }
            }
            Ok(Self(by_attr))
        } else {
            bail!("Expected hash in nix-instantiate output, got {:?}", &json);
        }
    }

    /// Writes list of all derivation paths into a temporary file, one per line
    pub fn dump_drvlist(&self) -> Result<TempPath> {
        let (f, drvlist) = tempfile::Builder::new()
            .prefix("drvlist.")
            .tempfile()?
            .into_parts();
        let mut w = BufWriter::new(f);
        for p in self.values().map(|e| &e.path) {
            w.write_all(p.as_os_str().as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        Ok(drvlist)
    }
}

impl Deref for DrvByAttr {
    type Target = HashMap<Attr, Drv>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use maplit::hashmap;

    #[test]
    fn package_name_version() {
        let p = Package::new("openssl", "1.0.2d");
        assert_eq!("openssl", p.pname());
        assert_eq!("1.0.2d", p.version());
    }

    #[test]
    fn format() {
        let p = Package::new("binutils", "2.32.1");
        assert_eq!("binutils-2.32.1", p.to_string());
    }

    #[test]
    fn parse() {
        assert_eq!(
            Package::new("exiv2", "0.27.1"),
            "exiv2-0.27.1".parse::<Package>().unwrap()
        );
        assert!("exiv2".parse::<Package>().is_err());
        assert!("linux-kernel".parse::<Package>().is_err());
        assert_eq!(
            Package::new("linux-kernel", "5.2"),
            "linux-kernel-5.2".parse::<Package>().unwrap()
        );
    }

    #[test]
    fn parse_should_collect_byattr() {
        let f = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/eval-release.json");
        assert_eq!(
            &DrvByAttr::parse_instantiation(f).expect("parse failed").0,
            &hashmap! {
                Attr::from("AMB-plugins") => Drv::new(
                    "AMB-plugins-0.8.1",
                    "/nix/store/hcpm7hwmn0xqaz2dr0sf7xnqscy7i2ar-AMB-plugins-0.8.1.drv"),
                Attr::from("CoinMP") => Drv::new(
                    "CoinMP-1.8.4",
                    "/nix/store/v92akqqn6acdcixqpdc7y0gxnmk1dlax-CoinMP-1.8.4.drv"),
                Attr::from("EBTKS") => Drv::new(
                    "EBTKS-2017-09-23",
                    "/nix/store/35gd8h8r7wysvapy7hpfh44fg88693aq-EBTKS-2017-09-23.drv"),
                Attr::from("EmptyEpsilon") => Drv::new(
                    "empty-epsilon-2020.04.09",
                    "/nix/store/k47jnzwnjmscxyc7qymc8crb1gi61zw6-empty-epsilon-2020.04.09.drv"),
            } // AAAAAASomeThingsFailToEvaluate has no arch attributes
              // AgdaSheaves has empty arch attributes
              // AgdaStdlib misses a version
        );
    }

    #[test]
    fn parse_empty_file_should_fail() {
        assert!(DrvByAttr::parse_instantiation("/dev/null").is_err());
    }
}
