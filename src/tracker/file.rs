//! Simple ticket tracker which just creates local files.

use super::{Issue, Tracker};
use crate::Ticket;

use colored::*;
use std::fs;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Cannot access file for ticket {}", 0)]
    IO(String, #[source] std::io::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct File;

impl File {
    pub fn new() -> Self {
        Self
    }
}

fn file_name(iterdir: &Path, tkt: &Ticket) -> PathBuf {
    iterdir.join(format!("ticket.{}.md", &tkt.name()))
}

impl Tracker for File {
    fn create_issues(&self, tickets: Vec<Ticket>, dir: &Path) -> Result<(), super::Error> {
        for tkt in tickets {
            let f = file_name(dir, &tkt);
            info!("{}: {}", tkt.name().yellow(), f.display());
            fs::File::create(f)
                .and_then(|f| writeln!(BufWriter::new(f), "{:#}", tkt))
                .map_err(|e| Error::IO(tkt.name().to_owned(), e))?;
        }
        Ok(())
    }

    // not supported
    fn search(&self) -> Result<Vec<Issue>, super::Error> {
        Ok(Vec::new())
    }

    fn name(&self) -> String {
        "File".into()
    }
}
