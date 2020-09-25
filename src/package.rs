//! Nix package abstractions.
//!
//! This module contains basic types for [`Package`] and [`Maintainer`] as well as methods for
//! querying Nix about available packages.

use anyhow::{ensure, Context, Result};
use colored::*;
use lazy_static::lazy_static;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, FromStr};
use std::sync::atomic::{AtomicI64, Ordering};
use tempfile::{NamedTempFile, TempPath};
use thiserror::Error;

/// Maintainer Github handle
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
#[serde(untagged)] // see https://serde.rs/enum-representations.html
pub enum Maintainer {
    Structured {
        github: Option<SmolStr>,
        email: Option<SmolStr>,
    },
    Unstructured(SmolStr),
}

impl Maintainer {
    #[allow(dead_code)]
    pub fn new(github: &str) -> Self {
        Maintainer::Structured {
            email: None,
            github: Some(SmolStr::new(github)),
        }
    }
}

/// Helper to get a quick list of package maintainers' GitHub handles or e-mail addresses
pub fn maintainer_contacts(maint: &[Maintainer]) -> Vec<&SmolStr> {
    maint
        .iter()
        .filter_map(|m| match m {
            Maintainer::Structured { github, .. } => github.as_ref(),
            _ => None,
        })
        .collect()
}

/// packages.json data structure as emitted by `nix-env -qa --json`. Some unimportant fields
/// omitted.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PkgInfo {
    pub name: SmolStr,
    pub pname: SmolStr,
    pub version: SmolStr,
    pub system: SmolStr,
    pub meta: PkgMeta,
}

/// Metadata section in packages.json output. We include only the interesting fields here.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PkgMeta {
    #[serde(default)]
    available: bool,
    #[serde(default)]
    pub maintainers: Vec<Maintainer>,
}

/// Package build architecture to consider
pub static ARCH: &str = "x86_64-linux";

/// Nix attribute name. Can also be a dotted expression like pythonPackages.docutils
pub type Attr = SmolStr;

/// List of all available packages as emitted by `nix-env -qa --json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllPackages {
    pub packages: HashMap<Attr, PkgInfo>,
}

impl AllPackages {
    /// Get comprehensive list of packages by running nix-env -qa --json.
    ///
    /// - workdir: nixpkgs dir with checked out branch
    pub fn query(workdir: &Path) -> Result<Self> {
        info!(
            "Querying all packages in {}",
            workdir.to_string_lossy().green()
        );
        let mut cmd = Command::new("nix-build");
        cmd.args(&["-E", include_str!("packages-json.nix")])
            .env("NIX_PATH", "nixpkgs=.")
            .current_dir(&workdir);
        debug!("Running: {:?}", cmd);
        let out = cmd.output().context("Cannot exec nix-build")?;
        ensure!(
            out.status.success(),
            "nix-build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let packages_json =
            PathBuf::from(String::from_utf8(out.stdout)?.trim()).join("packages.json");
        let parse = || -> Result<Self> {
            Ok(serde_json::from_reader(BufReader::new(File::open(
                &packages_json,
            )?))?)
        };
        let mut res = parse().with_context(|| format!("while parsing {:?}", packages_json))?;
        res.packages
            .retain(|_, v| v.meta.available && v.system == ARCH);
        Ok(res)
    }

    /// Instantiates all derivation paths (.drv files)
    pub fn ensure_drvs(&self, workdir: &Path) -> Result<TempPath> {
        let todo: Vec<_> = self.packages.keys().collect();
        info!("Instantiating derivations");
        let still_open = AtomicI64::new(todo.len() as i64);
        let tick = todo.len() as i64 % 250;
        let res = todo
            .into_par_iter()
            .chunks(50)
            .map(|attrs| {
                let n = still_open.fetch_sub(attrs.len() as i64, Ordering::Relaxed);
                if n > 0 && n % 250 == tick {
                    info!("{} drvs left", n.to_string().yellow());
                }
                let mut cmd = Command::new("nix-instantiate");
                cmd.args(&["--quiet", "<nixpkgs>"])
                    .env("NIX_PATH", "nixpkgs=.")
                    .current_dir(workdir);
                for attr in attrs {
                    cmd.args(&["-A", attr.as_str()]);
                }
                debug!("Running: {:?}", cmd);
                let out = cmd
                    .output()
                    .with_context(|| format!("Errors while executing {:?}", cmd))?;
                if !out.status.success() {
                    error!(
                        "Error while instantiating:\n{}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
                Ok(out)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut drvs = Vec::with_capacity(16000);
        for r in res {
            drvs.extend(
                str::from_utf8(&r.stdout)?
                    .split_terminator('\n')
                    .map(|d| d.rsplitn(2, '!').nth(1).unwrap_or(d))
                    .map(|s| s.to_owned()),
            );
        }
        let (mut f, path) = NamedTempFile::new()?.into_parts();
        writeln!(f, "{}", drvs.join("\n"))?;
        Ok(path)
    }
}

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

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;

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
}
