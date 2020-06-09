use crate::package::{Maintainer, Package, VERSION_SPLIT};

use anyhow::{bail, ensure, Context, Result};
use colored::*;
use rayon::prelude::*;
use serde::Deserialize;
use serde_json::Value;
use smallstr::SmallString;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::str;
use subprocess::Exec;
use tempfile::TempPath;

pub type Attr = SmallString<[u8; 20]>;
pub type DrvPath = PathBuf;

#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct Eval {
    pub name: Package,
    #[serde(rename = "drvPath")]
    pub drv: DrvPath,
}

impl Eval {
    #[allow(unused)]
    pub fn new<D: AsRef<Path>>(name: &str, drv: D) -> Self {
        Self {
            name: name.parse().unwrap(),
            drv: DrvPath::from(drv.as_ref()),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ByAttr(HashMap<Attr, Eval>);

impl ByAttr {
    fn parse_instantiation<P: AsRef<Path>>(out_json: P) -> Result<Self> {
        debug!(
            "Parsing nix-instantiate JSON output in {}",
            out_json.as_ref().display()
        );
        let json: Value = serde_json::from_reader(File::open(out_json.as_ref())?)?;
        // see fixtures/eval-release.json for expected file format
        if let Value::Object(map) = json {
            let mut by_attr = HashMap::with_capacity(map.len());
            for (attr, val) in map {
                if let Value::Object(pkg) = val {
                    for (arch, attrs) in pkg {
                        match (arch, attrs) {
                            (arch, obj @ Value::Object(_)) if arch == "x86_64-linux" => {
                                if let Ok(eval) = serde_json::from_value::<Eval>(obj) {
                                    if VERSION_SPLIT.is_match(&eval.name.as_str()) {
                                        by_attr.insert(Attr::from_str(&attr), eval);
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

    /// Write all derivation paths into a temporary file. It is the caller's duty to delete the
    /// file after use.
    pub fn dump_drvlist(&self) -> Result<TempPath> {
        let (f, drvlist) = tempfile::Builder::new()
            .prefix("drvlist.")
            .tempfile()?
            .into_parts();
        let mut w = BufWriter::new(f);
        for drv in self.values().map(|e| &e.drv) {
            w.write_all(drv.as_os_str().as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        Ok(drvlist)
    }

    pub fn intersect_pkgs(&self, pkgs: &[&Package]) -> Self {
        let mut res = HashMap::new();
        for (a, e) in self.iter().filter(|(_, e)| pkgs.contains(&&e.name)) {
            res.insert(a.clone(), e.clone());
        }
        Self(res)
    }
}

impl Deref for ByAttr {
    type Target = HashMap<Attr, Eval>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn instantiate(workdir: &Path) -> Result<TempPath> {
    let (f, tmp) = tempfile::Builder::new()
        .prefix("eval-release.")
        .tempfile()?
        .into_parts();
    let cap = Exec::cmd("nix-instantiate")
        .args(&[
            "--strict",
            "--eval-only",
            "--json",
            "maintainers/scripts/eval-release.nix",
        ])
        .env(
            "GC_INITIAL_HEAP_SIZE",
            env::var("GC_INITIAL_HEAP_SIZE").unwrap_or_else(|_| "2_000_000_000".to_owned()),
        )
        .env("NIX_PATH", "nixpkgs=.")
        .cwd(workdir)
        .stdout(f)
        .capture()
        .context("Failed to spawn 'nix-instatiate eval-release.nix'")?;
    ensure!(
        cap.success(),
        "nix-instatiate failed with {:?}",
        cap.exit_status
    );
    Ok(tmp)
}

/// Recursively expand all drvs starting from nixos/release-combined.nix by inspecting direct
/// dependencies and Hydra aggregates
///
/// - workdir: nixpkgs dir with checked out branch
pub fn all_derivations(workdir: &Path) -> Result<ByAttr> {
    info!(
        "Querying all packages in {} - this may take a while",
        workdir.to_string_lossy().green()
    );
    let tmp = instantiate(workdir)?;
    let res = ByAttr::parse_instantiation(&tmp).with_context(|| {
        format!(
            "Failed to parse nix-instantiate output (retained in {:?})",
            tmp.keep().unwrap()
        )
    })?;
    Ok(res)
}

pub fn ensure_drvs_exist(workdir: &Path, drvs: &ByAttr) -> Result<usize> {
    let todo: Vec<_> = drvs.iter().filter(|(_, e)| !e.drv.exists()).collect();
    if todo.is_empty() {
        return Ok(0);
    }
    info!(
        "{} drvs don't exist yet, instantiating",
        todo.len().to_string().yellow()
    );
    let res = todo
        .into_par_iter()
        .chunks(50)
        .map(|attrs| {
            let mut cmd = Command::new("nix-instantiate");
            cmd.arg("<nixpkgs>")
                .env("NIX_PATH", "nixpkgs=.")
                .current_dir(workdir);
            for (attr, _) in attrs {
                cmd.arg("-A").arg(attr.as_str());
            }
            debug!("exec: {:?}", cmd);
            cmd.output()
        })
        .collect::<Result<Vec<process::Output>, _>>()
        .context("Errors while executing nix-instantiate")?;
    for out in &res {
        ensure!(out.status.success(), "Error while instantiating {:?}", out);
    }
    Ok(res.len())
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct Ping {
    pub handle: Maintainer,
    #[serde(rename = "pkgName")]
    pub package: Attr,
}

/// Query lists of maintainers for a given iter of package attributes (not names!).
pub fn maintainers<'a>(
    workdir: &'_ Path,
    relevant_pkgs: impl Iterator<Item = &'a Attr>,
) -> Result<Vec<Ping>> {
    let attrs: Vec<Vec<&Attr>> = relevant_pkgs.map(|p| vec![p]).collect();
    let changedattrs = tempfile::Builder::new().prefix("changedattrs").tempfile()?;
    serde_json::to_writer(&changedattrs, &attrs)
        .with_context(|| format!("Failed to write temp file {:?}", changedattrs))?;
    let cap = Exec::cmd("nix-instantiate")
        .args(&[
            "--strict",
            "--eval-only",
            "--json",
            "-E",
            include_str!("maintainers.nix"),
            "--arg",
            "changedattrsjson",
        ])
        .arg(changedattrs.path())
        .env("NIX_PATH", "nixpkgs=.")
        .cwd(workdir)
        .capture()
        .context("Failed to spawn nix-instatiate")?;
    Ok(serde_json::from_slice(&cap.stdout).context("Cannot parse maintainers.nix output")?)
}

#[cfg(test)]
mod test {
    use super::*;
    use maplit::hashmap;

    #[test]
    fn parse_should_collect_byattr() {
        let f = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/eval-release.json");
        assert_eq!(
            &ByAttr::parse_instantiation(f).expect("parse failed").0,
            &hashmap! {
                Attr::from("AMB-plugins") => Eval::new(
                    "AMB-plugins-0.8.1",
                    "/nix/store/hcpm7hwmn0xqaz2dr0sf7xnqscy7i2ar-AMB-plugins-0.8.1.drv"),
                Attr::from("CoinMP") => Eval::new(
                    "CoinMP-1.8.4",
                    "/nix/store/v92akqqn6acdcixqpdc7y0gxnmk1dlax-CoinMP-1.8.4.drv"),
                Attr::from("EBTKS") => Eval::new(
                    "EBTKS-2017-09-23",
                    "/nix/store/35gd8h8r7wysvapy7hpfh44fg88693aq-EBTKS-2017-09-23.drv"),
                Attr::from("EmptyEpsilon") => Eval::new(
                    "empty-epsilon-2020.04.09",
                    "/nix/store/k47jnzwnjmscxyc7qymc8crb1gi61zw6-empty-epsilon-2020.04.09.drv"),
            } // AAAAAASomeThingsFailToEvaluate has no arch attributes
              // AgdaSheaves has empty arch attributes
              // AgdaStdlib misses a version
        );
    }

    #[test]
    fn parse_empty_file_should_fail() {
        assert!(ByAttr::parse_instantiation("/dev/null").is_err());
    }
}
