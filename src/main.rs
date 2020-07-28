#[macro_use]
extern crate log;

mod advisory;
mod count;
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

use anyhow::{bail, Context, Error};
use colored::*;
use env_logger::Env;
use futures::stream::{FuturesUnordered, StreamExt};
use std::borrow::Borrow;
use std::io::stdout;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use tokio::runtime::Runtime;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, StructOpt)]
#[structopt(
    rename_all = "kebab",
    after_help = "\
    Set RUST_LOG=survey=debug in the environment to get full logging output.
    "
)]
pub struct Opt {
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
    /// Base directory for vulnix JSON outputs and tickets (excluding iteration subdir)
    #[structopt(
        short = "o",
        long = "outdir",
        value_name = "DIR",
        default_value = "iterations",
        parse(from_os_str)
    )]
    basedir: PathBuf,
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
    /// Ping package maintainers
    #[structopt(short = "m", long)]
    ping_maintainers: bool,
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
    /// Constructs per-iteration directory from basedir and iteration number.
    fn iterdir(&self) -> PathBuf {
        self.basedir.join(self.iteration.to_string())
    }

    /// Full path to JSON file containing vulnix scan results
    fn vulnix_json(&self, branch: &str) -> PathBuf {
        self.iterdir().join(format!("vulnix.{}.json", branch))
    }
}

async fn count(opt: &Opt) -> Result<()> {
    if opt.repo.is_none() {
        warn!("No repository given");
    }
    let tracker = create_tracker(opt)?;
    serde_json::to_writer_pretty(
        stdout().lock(),
        &count::count(tracker.borrow())
            .await
            .context("Failed to search issues")?,
    )
    .context("broken pipe")
}

async fn create(tkt: Ticket, iterdir: &Path, tracker: &dyn Tracker) -> Result<()> {
    let name = tkt.name().to_owned();
    let tkt = tracker
        .create_issue(tkt)
        .await
        .with_context(|| format!("Failed to create issue for {}", name.purple().bold()))?;
    tkt.write(&iterdir.join(tkt.file_name()))?;
    Ok(())
}

// GitHub won't accept more than 30 issues in a batch
const MAX_ISSUES: usize = 30;

async fn make_issues(
    mut tickets: Vec<Ticket>,
    iterdir: &Path,
    tracker: &dyn Tracker,
) -> Result<()> {
    info!("Creating issues");
    tickets.retain(|tkt| {
        if iterdir.join(tkt.file_name()).exists() {
            info!("{}: skipping, file exists", tkt.name().yellow());
            false
        } else {
            true
        }
    });
    let len = tickets.len();
    let mut handles: FuturesUnordered<_> = tickets
        .into_iter()
        .take(MAX_ISSUES)
        .map(|tkt| create(tkt, iterdir, tracker))
        .collect();
    while let (Some(res), remaining) = handles.into_future().await {
        if let Err(e) = res {
            error!("{:#}", e);
        }
        handles = remaining;
    }
    if len > MAX_ISSUES {
        warn!("Not all issues created due to rate limits. Wait 5 minutes and rerun with '-R'");
    }
    Ok(())
}

fn create_tracker(opt: &Opt) -> Result<Box<dyn Tracker>> {
    Ok(match (&opt.repo, &opt.github_token) {
        (Some(repo), Some(token)) => Box::new(tracker::GitHub::new(token.to_string(), repo)?),
        (Some(_), None) => bail!(
            "No Github access token given either as option or via the GITHUB_TOKEN environment \
             variable"
        ),
        (_, _) => Box::new(tracker::Null::new()),
    })
}

async fn roundup(opt: &Opt, r_opt: &Roundup) -> Result<()> {
    let branches = Branches::with_repo(&r_opt.branches, &r_opt.nixpkgs)?;
    let dir = r_opt.iterdir();
    let tracker = create_tracker(opt)?;
    let sbb = if r_opt.no_run {
        branches.load(r_opt)?
    } else {
        branches.scan(r_opt)?
    };
    make_issues(
        ticket::ticket_list(r_opt.iteration, sbb, r_opt.ping_maintainers),
        &dir,
        tracker.borrow(),
    )
    .await
}

async fn run() -> Result<()> {
    dotenv::dotenv().ok();
    let opt = Opt::from_args();
    match opt.command {
        Cmd::Roundup(ref r) => roundup(&opt, r).await,
        Cmd::Count => count(&opt).await,
    }
}

fn main() {
    env_logger::from_env(Env::default().default_filter_or("info")).init();
    if let Err(err) = Runtime::new().unwrap().block_on(run()) {
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
