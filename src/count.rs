use crate::tracker::Tracker;

use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    by_roundup: HashMap<usize, IssueCount>,
    total: IssueCount,
}

#[derive(Debug, Default, Serialize)]
pub struct IssueCount {
    issues: usize,
    open_cves: usize,
}

lazy_static! {
    static ref OPEN_CVE: Regex = Regex::new(r"\[ \] \[CVE-\d+-\d+\]").unwrap();
}

fn count_cves(body: &str) -> usize {
    OPEN_CVE.find_iter(body).count()
}

pub fn count(tracker: &dyn Tracker) -> Result<Counts> {
    let mut counts = Counts::default();
    let r_roundup = Regex::new(r"Vulnerability roundup (\d+):").unwrap();
    for iss in tracker.search()? {
        debug!("issue #{}: {}", iss.number, iss.title);
        if let Some(cap) = r_roundup.captures(&iss.title) {
            if let Ok(i) = cap[1].parse::<usize>() {
                let c = counts.by_roundup.entry(i).or_default();
                c.issues += 1;
                c.open_cves += count_cves(&iss.body);
            }
        }
    }
    counts.total = IssueCount {
        issues: counts.by_roundup.values().map(|c| c.issues).sum(),
        open_cves: counts.by_roundup.values().map(|c| c.open_cves).sum(),
    };
    Ok(counts)
}
