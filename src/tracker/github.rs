use super::{Issue, Tracker};
use crate::ticket::Ticket;

use clap::{crate_name, crate_version};
use colored::*;
use reqwest::blocking::Client;
use reqwest::header::*;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid GitHub Api response at {url}: {resp}")]
    Api {
        url: String,
        resp: String,
        #[source]
        e: serde_json::Error,
    },
    #[error("HTTP request error")]
    Request(#[from] reqwest::Error),
    #[error("Repository specification must be in the format <OWNER>/<REPO>")]
    RepoFormat,
    #[error("Trying to construct invalid HTTP header")]
    Header(#[from] http::header::InvalidHeaderValue),
    #[error("Cannot write issue file '{}'", 0)]
    Json(PathBuf, #[source] std::io::Error),
}

/// Shortcut
fn api_err(url: &str, resp: String, e: serde_json::Error) -> Error {
    Error::Api {
        url: url.to_string(),
        resp,
        e,
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// GitHub response to comment creation
#[derive(Deserialize, Debug, Clone)]
#[allow(unused)]
struct Comment {
    id: u64,
    url: String,
    html_url: String,
}

#[derive(Debug, Clone)]
struct UrlFor {
    issues: String,
    search: String,
}

impl UrlFor {
    fn new(repo: &RepoSpec) -> Self {
        Self {
            issues: format!("https://api.github.com/repos/{}/issues", repo),
            search: "https://api.github.com/search/issues".to_owned(),
        }
    }
}

/// Issue search results
#[derive(Deserialize, Debug, Clone, Default)]
struct Search {
    items: Vec<Issue>,
    total_count: usize,
}

#[derive(Debug, Clone)]
pub struct GitHub {
    client: Client,
    repo: RepoSpec,
    notify: bool,
    url_for: UrlFor,
}

impl GitHub {
    pub fn new(token: String, repo_spec: &str, notify: bool) -> Result<Self> {
        let repo = repo_spec.parse()?;
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, format!("token {}", token).parse()?);
        h.insert(ACCEPT, "application/vnd.github.v3+json".parse()?);
        h.insert(
            USER_AGENT,
            format!("{}/{}", crate_name!(), crate_version!()).parse()?,
        );
        let client = Client::builder().default_headers(h).build()?;
        let url_for = UrlFor::new(&repo);
        Ok(Self {
            client,
            repo,
            notify,
            url_for,
        })
    }

    fn create(&self, tkt: &Ticket) -> Result<Issue> {
        let url = &self.url_for.issues;
        let mut body = String::with_capacity(4096);
        tkt.render(&mut body, self.notify).ok();
        let res = self
            .client
            .post(url)
            .json(&json!({
                "title": tkt.summary(),
                "body": body,
                "labels": vec!["1.severity: security"]
            }))
            .send()?;
        let txt = res.text()?;
        serde_json::from_str(&txt).map_err(|e| api_err(url, txt, e))
    }

    fn related(&self, tkt: &Ticket) -> Result<Search> {
        let url = &self.url_for.search;
        let query = format!(
            "\
repo:{} is:open label:\"1.severity: security\" in:title \"Vulnerability roundup \" \" {}: \"",
            self.repo,
            tkt.name()
        );
        let res = self
            .client
            .get(url)
            .query(&[("q", query)])
            .send()?
            .error_for_status()?
            .text()?;
        serde_json::from_str(&res).map_err(|e| api_err(url, res, e))
    }

    fn comment(&self, number: u64, related: &[Issue]) -> Result<Comment> {
        let url = &format!("{}/{}/comments", self.url_for.issues, number);
        let related: Vec<String> = related.iter().map(|i| format!("#{}", i.number)).collect();
        let res = self
            .client
            .post(url)
            .json(&json!({
                "body": format!("See also: {}", related.join(", "))
            }))
            .send()?
            .error_for_status()?
            .text()?;
        serde_json::from_str(&res).map_err(|e| api_err(url, res, e))
    }

    fn create_and_comment(&self, tkt: &Ticket) -> Result<Issue> {
        let i = self.create(tkt)?;
        let rel = self.related(tkt)?;
        if !rel.items.is_empty() {
            self.comment(i.number, &rel.items)?;
        }
        Ok(i)
    }

    fn search_(&self, page: usize) -> Result<Search> {
        let url = &self.url_for.search;
        let query = format!(
            "repo:{} is:open label:\"1.severity: security\" in:title \"Vulnerability roundup\"",
            self.repo
        );
        let res = self
            .client
            .get(url)
            .query(&[("q", query), ("page", page.to_string())])
            .send()?
            .error_for_status()?
            .text()?;
        // debug!("GitHub: {}", res);
        serde_json::from_str(&res).map_err(|e| api_err(url, res, e))
    }
}

fn json_file(dir: &Path, tkt: &Ticket) -> PathBuf {
    dir.join(format!("github.{}.json", tkt.name()))
}

// GitHub won't accept more than 30 issues in a batch
const MAX_ISSUES: usize = 30;

#[derive(Debug, Serialize, Default)]
struct SavedIssue {
    ticket: Ticket,
    issue_id: u64,
    issue_url: String,
}

impl SavedIssue {
    fn write(&self, dir: &Path) -> Result<(), std::io::Error> {
        let mut f = File::create(json_file(dir, &self.ticket))?;
        let w = BufWriter::new(f.try_clone().unwrap());
        serde_json::to_writer_pretty(w, &self)?;
        writeln!(f)?;
        Ok(())
    }
}

impl Tracker for GitHub {
    fn create_issues(&self, mut tickets: Vec<Ticket>, dir: &Path) -> Result<(), super::Error> {
        tickets.retain(|tkt| !json_file(dir, tkt).exists());
        for tkt in tickets.iter().take(MAX_ISSUES) {
            let i = self.create_and_comment(tkt)?;
            info!("{}: {}", tkt.name(), i.html_url.purple());
            SavedIssue {
                issue_id: i.number,
                issue_url: i.url,
                ticket: tkt.clone(),
            }
            .write(dir)
            .map_err(|e| Error::Json(json_file(dir, tkt), e))?;
            std::thread::sleep(Duration::new(1, 0));
        }
        if tickets.len() > MAX_ISSUES {
            warn!("Not all issues created due to rate limits. Wait 5 minutes and rerun with '-R'");
        }
        Ok(())
    }

    fn search(&self) -> Result<Vec<Issue>, super::Error> {
        let mut iss = Vec::new();
        for page in 1..100 {
            let mut s = self.search_(page)?;
            iss.append(&mut s.items);
            if iss.len() >= s.total_count {
                break;
            }
        }
        Ok(iss)
    }

    fn name(&self) -> String {
        format!("GitHub[{}]", self.repo)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct RepoSpec {
    owner: String,
    repo: String,
}

impl RepoSpec {
    #[allow(unused)]
    fn new<S: Into<String>, T: Into<String>>(owner: S, repo: T) -> Self {
        Self {
            owner: owner.into(),
            repo: repo.into(),
        }
    }
}

impl FromStr for RepoSpec {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut elem = s.split('/');
        let owner = elem.next().ok_or(Error::RepoFormat)?.to_owned();
        let repo = elem.next().ok_or(Error::RepoFormat)?.to_owned();
        if owner.is_empty() || repo.is_empty() || elem.next().is_some() {
            Err(Error::RepoFormat)
        } else {
            Ok(Self { owner, repo })
        }
    }
}

impl fmt::Display for RepoSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.repo)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn repospec_parse() {
        assert_eq!(RepoSpec::new("foo", "bar"), "foo/bar".parse().unwrap());
        assert!("".parse::<RepoSpec>().is_err());
        assert!("/".parse::<RepoSpec>().is_err());
        assert!("/foo".parse::<RepoSpec>().is_err());
        assert!("foo/".parse::<RepoSpec>().is_err());
        assert!("foo/bar/".parse::<RepoSpec>().is_err());
    }

    #[test]
    fn repospec_string() {
        assert_eq!(RepoSpec::new("owner", "repo").to_string(), "owner/repo");
    }
}
