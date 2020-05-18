mod github;
mod null;

use async_trait::async_trait;
pub use github::GitHub;
pub use null::Null;

use crate::ticket::Ticket;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    GitHub(#[from] github::Error),
}

#[async_trait]
pub trait Tracker {
    /// Create issue and return possibly modified ticket
    async fn create_issue(&self, tkt: Ticket) -> Result<Ticket, Error>;
}
