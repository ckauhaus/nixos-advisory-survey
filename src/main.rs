#[macro_use]
extern crate log;

mod advisory;
mod branches;
mod count;
mod filter;
mod scan;
mod source;
#[cfg(test)]
mod tests;
mod ticket;
mod tracker;

use crate::branches::{Branch, Branches};
use crate::ticket::Ticket;
use crate::tracker::Tracker;

use anyhow::{bail, Context, Error};
use colored::*;
use env_logger::Env;
use std::borrow::Borrow;
use std::io::stdout;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, StructOpt)]
#[structopt(
    rename_all = "kebab",
    after_help = "\
    Set RUST_LOG=survey=debug in the environment to get full logging output.
    "
)]
pub struct Opt {
    /// Base directory for vulnix JSON outputs and tickets (excluding iteration subdir)
    #[structopt(
        short = "o",
        long = "outdir",
        value_name = "DIR",
        default_value = "iterations",
        parse(from_os_str)
    )]
    basedir: PathBuf,
    /// Create GitHub issues in this repository
    #[structopt(short, long, global = true, value_name = "USER/REPO")]
    repo: Option<String>,
    /// GitHub access token
    ///
    /// Alternatively set the GITHUB_TOKEN environment variable
    #[structopt(short, long, global = true, env = "GITHUB_TOKEN")]
    github_token: Option<String>,
    #[structopt(subcommand)]
    command: Cmd,
}

impl Default for Opt {
    fn default() -> Self {
        Opt {
            repo: None,
            github_token: None,
            command: Cmd::Roundup(Roundup::default()),
            basedir: PathBuf::from("iterations"),
        }
    }
}

#[derive(Debug, Clone, StructOpt)]
pub enum Cmd {
    /// Creates vulnerability roundup and (optionally) submit issues to a tracker.
    Roundup(Roundup),
    /// Counts open issues and CVEs.
    Count,
}

#[derive(Debug, Clone, StructOpt, Default)]
pub struct Roundup {
    /// Path to `nixpkgs` checkout
    #[structopt(
        short,
        long,
        value_name = "PATH",
        default_value = "nixpkgs",
        parse(from_os_str)
    )]
    nixpkgs: PathBuf,
    /// Directory for updated whitelists
    #[structopt(
        short = "w",
        long,
        value_name = "DIR",
        default_value = "whitelists",
        parse(from_os_str)
    )]
    whitelist_dir: PathBuf,
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
    /// Keep temporary files for debugging
    #[structopt(short, long)]
    keep: bool,
    /// Ping package maintainers
    #[structopt(short = "m", long)]
    ping_maintainers: bool,
    /// Only consider packages found in at least one Nix store dump in DIR
    #[structopt(short, long, value_name = "DIR", parse(from_os_str))]
    filter: Option<PathBuf>,
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

impl Roundup {
    /// Full path to this iterations data dir
    fn iterdir(&self, base: &Path) -> PathBuf {
        base.join(self.iteration.to_string())
    }
}

fn tracker(opt: &Opt, ping_maintainers: bool) -> Result<Box<dyn Tracker>> {
    Ok(match (&opt.repo, &opt.github_token) {
        (Some(repo), Some(token)) => Box::new(tracker::GitHub::new(
            token.to_string(),
            repo,
            ping_maintainers,
        )?),
        (Some(_), None) => bail!(
            "No GitHub access token given either as option or via the GITHUB_TOKEN environment \
             variable"
        ),
        (_, _) => Box::new(tracker::File::new()),
    })
}

fn count(opt: &Opt) -> Result<()> {
    if opt.repo.is_none() {
        warn!("No repository given");
    }
    let tracker = tracker(opt, false)?;
    serde_json::to_writer_pretty(
        stdout().lock(),
        &count::count(tracker.borrow()).context("Failed to search issues")?,
    )
    .context("broken pipe")
}

fn roundup(opt: &Opt, r_opt: &Roundup) -> Result<()> {
    let branches = Branches::with_repo(&r_opt.branches, &r_opt.nixpkgs)?;
    let tracker = tracker(opt, r_opt.ping_maintainers)?;
    let iterdir = r_opt.iterdir(&opt.basedir);
    let sbb = if r_opt.no_run {
        branches.load(&iterdir)?
    } else {
        branches.scan(&iterdir, r_opt)?
    };
    let tickets = ticket::ticket_list(r_opt.iteration, sbb);
    if !tickets.is_empty() {
        info!("Creating issues in {} tracker", tracker.name().green());
        tracker.create_issues(tickets, &r_opt.iterdir(&opt.basedir))?;
    }
    Ok(())
}

fn run() -> Result<()> {
    dotenv::dotenv().ok();
    let opt = Opt::from_args();
    match opt.command {
        Cmd::Roundup(ref r) => roundup(&opt, r),
        Cmd::Count => count(&opt),
    }
}

fn main() {
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    if let Err(err) = run() {
        for e in err.chain() {
            error!("{}", e);
            // reqwest seems to fold all causes into its head error
            if e.downcast_ref::<reqwest::Error>().is_some() {
                break;
            }
        }
        std::process::exit(1);
    }
}
