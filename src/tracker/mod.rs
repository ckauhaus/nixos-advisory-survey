mod file;
mod github;

use crate::ticket::Ticket;

pub use file::File;
pub use github::GitHub;
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    GitHub(#[from] github::Error),
    #[error(transparent)]
    File(#[from] file::Error),
}

/// Individual issue as returned by issue search/count
#[derive(Deserialize, Debug, Clone, Default)]
pub struct Issue {
    pub id: u64,
    pub url: String,
    pub html_url: String,
    pub number: u64,
    pub title: String,
    pub body: String,
}

pub trait Tracker {
    /// Creates as many issues as rate limits allow
    fn create_issues(&self, tkt: Vec<Ticket>, iterdir: &Path) -> Result<(), Error>;

    /// Returns all open isssues
    fn search(&self) -> Result<Vec<Issue>, Error>;
}
