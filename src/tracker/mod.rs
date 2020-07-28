mod github;
mod null;

use crate::ticket::Ticket;

use async_trait::async_trait;
pub use github::GitHub;
pub use null::Null;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    GitHub(#[from] github::Error),
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

#[async_trait]
pub trait Tracker {
    /// Create issue and return possibly modified ticket
    async fn create_issue(&self, tkt: Ticket) -> Result<Ticket, Error>;

    /// Returns all open isssues
    async fn search(&self) -> Result<Vec<Issue>, Error>;
}
