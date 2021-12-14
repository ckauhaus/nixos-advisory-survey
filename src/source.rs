//! Package list processing.
//!
//! Available packages are sourced from nix-env and postprocessed.
//! This module contains basic types for [`Package`] and [`Maintainer`]

use anyhow::{ensure, Context, Result};
use colored::*;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, FromStr};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Build architecture to consider. Packages not available for this system will be discarded.
pub static SYSTEM: &str = "x86_64-linux";

type Str = SmolStr;

/// Maintainer GitHub handle
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
#[serde(untagged)] // see https://serde.rs/enum-representations.html
pub enum Maintainer {
    Structured {
        github: Option<Str>,
        email: Option<Str>,
    },
    Unstructured(Str),
    Nested(Vec<Maintainer>),
}

impl Maintainer {
    #[allow(dead_code)]
    pub fn new(github: &str) -> Self {
        Maintainer::Structured {
            email: None,
            github: Some(Str::new(github)),
        }
    }
}

/// Helper to get a quick list of package maintainers' GitHub handles
pub fn maintainer_contacts(maint: &[Maintainer]) -> Vec<&Str> {
    maint
        .iter()
        .filter_map(|m| match m {
            Maintainer::Structured {
                github: Some(ref g),
                ..
            } => Some(vec![g]),
            Maintainer::Nested(sub) => Some(maintainer_contacts(sub)),
            _ => None,
        })
        .flatten()
        .collect()
}

/// packages.json data structure as emitted by `nix-env -qa --json`. Some unimportant fields
/// omitted.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NixEnvPkg {
    #[serde(rename = "name")]
    pub pkg: Str,
    pub system: Str,
    pub meta: PkgMeta,
}

/// Metadata section in packages.json output. We include only the interesting fields here.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PkgMeta {
    #[serde(default)]
    pub available: bool,
    #[serde(default)]
    pub maintainers: Vec<Maintainer>,
    #[serde(rename = "outputsToInstall", default)]
    pub outputs: Vec<Str>,
    #[serde(rename = "knownVulnerabilities", default)]
    pub known_vulnerabilities: Vec<Str>,
}

/// Nix attribute name. Can also be a dotted expression like pythonPackages.docutils
pub type Attr = Str;

#[derive(Debug, Default, Deserialize)]
pub struct Patches(HashMap<Attr, Vec<String>>);

impl Deref for Patches {
    type Target = HashMap<Attr, Vec<String>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Patches {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// List of all available packages.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllPackages {
    pub packages: HashMap<Attr, NixEnvPkg>,
}

impl AllPackages {
    /// Gets comprehensive list of packages by running `nix-env -qa --json`.
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
        debug!("{:?}", cmd);
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
        info!(
            "{} pkgs in {}",
            res.packages.len().to_string().yellow(),
            packages_json.display()
        );
        res.packages.retain(|_, v| {
            v.meta.available && v.system == SYSTEM && Package::from_str(&v.pkg).is_ok()
        });
        Ok(res)
    }

    /// Instantiates all derivation paths (.drv files) and return applied patches
    pub fn discover_patches(&self, workdir: &Path) -> Result<Patches> {
        let todo: Vec<_> = self.packages.keys().collect();
        let (f, tmp) = NamedTempFile::new()?.into_parts();
        {
            let mut w = BufWriter::new(f);
            writeln!(w, "{{ pkgs }}: [")?;
            for a in todo {
                writeln!(w, "pkgs.{}", a)?;
            }
            writeln!(w, "]")?;
        }
        info!("Examining derivations for patches");
        let mut cmd = Command::new("nix-instantiate");
        cmd.args(&[
            "--quiet",
            "--eval",
            "--strict",
            "--show-trace",
            "--json",
            "--expr",
            include_str!("listpatches.nix"),
            "--arg",
            "allPackages",
        ])
        .arg(&tmp)
        .env("NIX_PATH", "nixpkgs=.")
        .current_dir(workdir);
        debug!("{:?}", cmd);
        let out = cmd.output().context("Cannot to exec nix-instantiate")?;
        ensure!(
            out.status.success(),
            "Command failed: {:?} - keeping {} for reference\n{}",
            cmd,
            tmp.keep()?.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).with_context(|| {
            format!(
                "Failed to parse patch list: {}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&NixEnvPkg) -> bool,
    {
        self.packages.retain(|_, pi| match f(pi) {
            true => {
                debug!("present in Nix stores: {}", pi.pkg.to_string().green());
                true
            }
            false => {
                debug!(" absent in Nix stores: {}", pi.pkg.to_string().red());
                false
            }
        })
    }
}

/// Nix package name. Must contain a dash followed by a version
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Package {
    pub name: Str,
    v_idx: usize,
}

impl Package {
    #[allow(unused)]
    fn new<S: AsRef<str>>(pname: S, version: S) -> Self {
        let mut name = pname.as_ref().to_owned();
        name.push('-');
        name.push_str(version.as_ref());
        Self {
            name: Str::from(name),
            v_idx: pname.as_ref().len() + 1,
        }
    }

    pub fn pname(&self) -> &str {
        &self.name[..self.v_idx - 1]
    }

    pub fn version(&self) -> &str {
        &self.name[self.v_idx..]
    }
}

impl fmt::Display for Package {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.name)
    }
}

impl PartialEq<str> for Package {
    fn eq(&self, other: &str) -> bool {
        self.name.eq(other)
    }
}

impl PartialEq<Str> for Package {
    fn eq(&self, other: &Str) -> bool {
        self.name.eq(other)
    }
}

impl From<Package> for String {
    fn from(pkg: Package) -> Self {
        pkg.to_string()
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
                name: Str::from(s),
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
    use serde_json::json;

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
    fn parse_maintainers() {
        let nixenv_json = r#"
{
  "packages": {
    "grilo": {
      "name": "grilo-0.3.12",
      "pname": "grilo",
      "version": "0.3.12",
      "system": "x86_64-linux",
      "meta": { "maintainers": [ "unstructured1", "unstructured2" ] }
    },
    "grim": {
      "name": "grim-1.3.1",
      "pname": "grim",
      "version": "1.3.1",
      "system": "x86_64-linux",
      "meta": {
        "maintainers": [
          {
            "email": "mail@address",
            "github": "structured1"
          }
        ]
      }
    }
  }
}
"#;
        let n = serde_json::from_str::<AllPackages>(&nixenv_json)
            .unwrap()
            .packages;
        assert_eq!(
            n["grilo"].meta.maintainers,
            vec![
                Maintainer::Unstructured("unstructured1".into()),
                Maintainer::Unstructured("unstructured2".into())
            ]
        );
        assert_eq!(
            maintainer_contacts(&n["grim"].meta.maintainers),
            vec!["structured1"]
        );
    }

    #[test]
    fn parse_nested_maintainers() {
        let nixenv_json = r#"
{
  "packages": {
    "sway-contrib.grimshot": {
      "name": "grimshot-1.5",
      "pname": "grimshot",
      "version": "1.5",
      "system": "x86_64-linux",
      "meta": {
        "maintainers": [
          [
            {
              "email": "nest1@gmail.com",
              "github": "nest1"
            },
            {
              "email": "nest2@example.com",
              "github": "nest2"
            }
          ],
          {
            "email": "outer@protonmail.com",
            "github": "outer"
          }
        ]
      }
    }
  }
}
"#;
        let n = serde_json::from_str::<AllPackages>(&nixenv_json)
            .unwrap()
            .packages;
        assert_eq!(
            maintainer_contacts(&n["sway-contrib.grimshot"].meta.maintainers),
            vec!["nest1", "nest2", "outer"]
        );
    }

    #[test]
    fn parse_known_vulnerabilities() {
        let p: AllPackages = serde_json::from_value(json!({
          "packages": {
            "libav": {
              "name": "libav-11.12",
              "system": "x86_64-linux",
              "meta": {
                "knownVulnerabilities": [
                  "CVE-2017-9051",
                  "CVE-2018-5684"
                ],
              }
            }
          }
        }))
        .unwrap();
        assert_eq!(
            p.packages["libav"].meta.known_vulnerabilities,
            vec!["CVE-2017-9051", "CVE-2018-5684"]
        );
    }
}
