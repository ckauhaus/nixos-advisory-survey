use super::Tracker;
use crate::ticket::Ticket;

use async_trait::async_trait;
use clap::{crate_name, crate_version};
use reqwest::header::*;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid GitHub API response: {res}")]
    API {
        res: String,
        #[source]
        e: serde_json::Error,
    },
    #[error("HTTP request error")]
    Request(#[from] reqwest::Error),
    #[error("Repository specification must be in the format <OWNER>/<REPO>")]
    RepoFormat,
    #[error("Trying to construct invalid HTTP header")]
    Header(#[from] http::header::InvalidHeaderValue),
    #[error("Invalid HTTP data")]
    HTTP(#[from] http::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// GitHub response to search
#[derive(Deserialize, Debug, Clone)]
struct Search {
    items: Vec<Issue>,
    total_count: u64,
}

/// GitHub response to issue creation/search
#[derive(Deserialize, Debug, Clone)]
struct Issue {
    id: u64,
    number: u64,
    url: String,
    html_url: String,
}

/// GitHub response to comment creation
#[derive(Deserialize, Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct GitHub {
    client: Client,
    repo: RepoSpec,
    url_for: UrlFor,
}

impl GitHub {
    pub fn new(token: String, repo_spec: &str) -> Result<Self> {
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
            url_for,
        })
    }

    async fn create(&self, tkt: &Ticket) -> Result<Issue> {
        let res = self
            .client
            .post(&self.url_for.issues)
            .json(&json!({
                "title": tkt.summary(),
                "body": tkt.to_string(),
                "labels": &["1.severity: security"]
            }))
            .send()
            .await?
            .text()
            .await?;
        serde_json::from_str(&res).map_err(|e| Error::API { res, e })
    }

    async fn related(&self, tkt: &Ticket) -> Result<Search> {
        let query = format!(
            "\
repo:{} is:open label:\"1.severity: security\" in:title \"Vulnerability roundup \" \" {}: \"",
            self.repo,
            tkt.name()
        );
        let res = self
            .client
            .get(&self.url_for.search)
            .query(&[("q", query)])
            .send()
            .await?
            .text()
            .await?;
        serde_json::from_str(&res).map_err(|e| Error::API { res, e })
    }

    async fn comment(&self, number: u64, related: &[Issue]) -> Result<Comment> {
        let related: Vec<String> = related.iter().map(|i| format!("#{}", i.number)).collect();
        let res = self
            .client
            .post(&format!("{}/{}/comments", self.url_for.issues, number))
            .json(&json!({
                "body": format!("See also: {}", related.join(", "))
            }))
            .send()
            .await?
            .text()
            .await?;
        serde_json::from_str(&res).map_err(|e| Error::API { res, e })
    }
}

#[async_trait]
impl Tracker for GitHub {
    async fn create_issue(&self, tkt: Ticket) -> Result<Ticket, super::Error> {
        let c = self.create(&tkt).await?;
        let rel = self.related(&tkt).await?;
        if !rel.items.is_empty() {
            self.comment(c.number, &rel.items).await?;
        }
        Ok(Ticket {
            issue_id: Some(c.number),
            issue_url: Some(c.html_url),
            ..tkt
        })
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
