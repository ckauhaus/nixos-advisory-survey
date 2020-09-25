use super::{Issue, Tracker};
use crate::Ticket;
use std::path::Path;

pub struct Null;

impl Null {
    pub fn new() -> Self {
        Self
    }
}

impl Tracker for Null {
    fn create_issues(&self, _tkt: Vec<Ticket>, _iterdir: &Path) -> Result<(), super::Error> {
        Ok(())
    }

    fn search(&self) -> Result<Vec<Issue>, super::Error> {
        Ok(Vec::default())
    }
}
