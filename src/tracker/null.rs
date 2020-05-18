use super::Tracker;
use crate::Ticket;
use async_trait::async_trait;

pub struct Null;

impl Null {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Tracker for Null {
    async fn create_issue(&self, tkt: Ticket) -> Result<Ticket, super::Error> {
        Ok(tkt)
    }
}
