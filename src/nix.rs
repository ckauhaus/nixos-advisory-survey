use crate::package::{Attr, DrvByAttr, Maintainer, Package};

use anyhow::{ensure, Context, Result};
use colored::*;
use rayon::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::str;
use subprocess::{CaptureData, Exec};
use tempfile::TempPath;

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
pub fn all_derivations(workdir: &Path) -> Result<DrvByAttr> {
    info!(
        "Querying all packages in {} - this may take a while",
        workdir.to_string_lossy().green()
    );
    let tmp = instantiate(workdir)?;
    let res = DrvByAttr::parse_instantiation(&tmp).with_context(|| {
        format!(
            "Failed to parse nix-instantiate output (retained in {:?})",
            tmp.keep().unwrap()
        )
    })?;
    Ok(res)
}

pub fn ensure_drvs_exist(workdir: &Path, drvs: &DrvByAttr) -> Result<usize> {
    let todo: Vec<_> = drvs.iter().filter(|(_, e)| !e.path.exists()).collect();
    if todo.is_empty() {
        return Ok(0);
    }
    info!(
        "{} drvs don't exist yet, instantiating",
        todo.len().to_string().yellow()
    );
    let res: Vec<CaptureData> = todo
        .into_par_iter()
        .chunks(50)
        .map(|attrs| {
            let mut cmd = Exec::cmd("nix-instantiate")
                .arg("<nixpkgs>")
                .env("NIX_PATH", "nixpkgs=.")
                .cwd(workdir);
            for (attr, _) in attrs {
                cmd = cmd.arg("-A").arg(attr.as_str());
            }
            debug!("exec: {}", cmd.to_cmdline_lossy());
            cmd.capture()
        })
        .collect::<Result<Vec<_>, _>>()
        .context("Errors while executing nix-instantiate")?;
    for cap in &res {
        ensure!(
            cap.exit_status.success(),
            "Error while instantiating:\n{}\n{}",
            cap.stdout_str(),
            cap.stderr_str()
        );
    }
    Ok(res.len())
}

/// List of maintainer notifications for a given package.
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct Ping {
    pub name: Package,
    pub maintainers: Vec<Maintainer>,
}

/// Query lists of maintainers for a given iter of package attributes (not names!).
pub fn collect_maintainers<'a>(
    workdir: &'_ Path,
    relevant_pkgs: impl Iterator<Item = &'a Attr>,
) -> Result<HashMap<Attr, Ping>> {
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
    Ok(serde_json::from_slice(&cap.stdout)
        .with_context(|| format!("Cannot parse maintainers.nix output: {}", cap.stdout_str()))?)
}
