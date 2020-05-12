#[macro_use]
extern crate log;

mod advisory;
mod nix;
mod package;
mod scan;
#[cfg(test)]
mod tests;
mod ticket;
mod tracker;

use crate::scan::{Branch, Branches};
use crate::ticket::Ticket;
use crate::tracker::Tracker;

use anyhow::{bail, Error};
use colored::*;
use env_logger::Env;
use std::borrow::Borrow;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, StructOpt, Default)]
#[structopt(rename_all = "kebab")]
pub struct Opt {
    /// Path to `nixpkgs` checkout
    #[structopt(
        short,
        long,
        value_name = "PATH",
        default_value = "nixpkgs-channels",
        parse(from_os_str)
    )]
    nixpkgs: PathBuf,
    /// Base directory for vulnix JSON outputs and tickets (excluding iteration subdir)
    #[structopt(
        short = "o",
        long = "outdir",
        value_name = "DIR",
        default_value = "iterations",
        parse(from_os_str)
    )]
    basedir: PathBuf,
    /// Directory for updated whitelists (expected to be pushed to `whitelist_url` eventually)
    #[structopt(
        short = "w",
        long,
        value_name = "DIR",
        default_value = "whitelists",
        parse(from_os_str)
    )]
    whitelist_dir: PathBuf,
    /// Base URL to load current whitelists from (release name will be appended)
    #[structopt(
        short = "W",
        long,
        value_name = "URL",
        default_value = "https://raw.githubusercontent.com/ckauhaus/nixos-vulnerability-roundup/\
                         master/whitelists"
    )]
    whitelist_url: String,
    /// Path to `vulnix` executable
    #[structopt(
        short,
        long,
        value_name = "PATH",
        default_value = "vulnix",
        parse(from_os_str)
    )]
    vulnix: PathBuf,
    /// Don't run vulnix (expects vulnix JSON output already present in iteration dir)
    #[structopt(short = "R", long)]
    no_run: bool,
    /// Create GitHub issues in this repository
    #[structopt(short, long, value_name = "USER/REPO")]
    repo: Option<String>,
    /// GitHub access token
    ///
    /// Alternatively set the GITHUB_TOKEN environment variable
    #[structopt(short, long, env = "GITHUB_TOKEN")]
    github_token: Option<String>,
    /// Nth survey iteration
    #[structopt(value_name = "N")]
    iteration: u32,
    /// List of nixpkgs branches to scan
    ///
    /// Format: BRANCH=COMMITID or just BRANCH (uses current branch head).
    /// Examples: "nixos-unstable=55f4cd48" or "nixos-18.09"
    #[structopt(value_name = "BRANCHES", required = true)]
    branches: Vec<Branch>,
}

impl Opt {
    /// Constructs per-iteration directory from basedir and iteration number
    pub fn iterdir(&self) -> PathBuf {
        self.basedir.join(self.iteration.to_string())
    }
}

fn create(tkt: Ticket, iterdir: &Path, tracker: &Option<Tracker>) -> Result<()> {
    let f = iterdir.join(tkt.file_name());
    if f.exists() {
        println!("{}: {}", tkt.name(), "skipping, file exists".purple());
        return Ok(());
    }
    print!("{}: ", tkt.name().yellow());
    if let Some(t) = tracker.borrow() {
        let (issue_id, issue_url) = t.create_issue(&tkt)?;
        print!("issue #{}, ", issue_id);
        tkt.write(&f, Some(&issue_url))?;
    } else {
        tkt.write(&f, None)?
    }
    println!("file '{}'", tkt.file_name().display());
    Ok(())
}

fn run() -> Result<()> {
    dotenv::dotenv().ok();
    let opt = Opt::from_args();
    let branches = Branches::with_repo(&opt.branches, &opt.nixpkgs)?;
    let dir = opt.iterdir();
    let tracker = match (&opt.repo, &opt.github_token) {
        (Some(repo), Some(token)) => Some(Tracker::connect_github(token.to_string(), repo)?),
        (Some(_), None) => bail!(
            "No Github access token given either as option or via the GITHUB_TOKEN environment \
             variable"
        ),
        (_, _) => None,
    };
    let scan_res = if opt.no_run {
        branches.load(&dir)?
    } else {
        branches.scan(&opt)?
    };
    println!("{}", "* Creating issues...".green());
    for tkt in ticket::ticket_list(opt.iteration, scan_res) {
        create(tkt, &dir, &tracker)?;
    }
    Ok(())
}

fn main() {
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    if let Err(err) = run() {
        if err.is::<tracker::Error>() {
            println!(); // flush partially printed lines
        }
        error!("{} {}", "Error:".red().bold(), err);
        if let Some(source) = err.source() {
            error!("{}", source);
        }
        std::process::exit(1);
    }
}
