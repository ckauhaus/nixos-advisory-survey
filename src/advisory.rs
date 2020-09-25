use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

type Result<T, E = AdvErr> = std::result::Result<T, E>;

lazy_static! {
    static ref CVESPEC: Regex = Regex::new(r"^CVE-(\d{4})-(\d+)$").unwrap();
}

/// Securty advisory identifier. Currently only CVEs are supported.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Advisory(SmolStr);

impl Advisory {
    /// Represent myself as numeric tuple if possible. This is needed for sorting CVEs.
    pub fn as_tuple(&self) -> (u16, u32) {
        let c = CVESPEC.captures(&self.0).expect("invalid CVE format");
        (c[1].parse().unwrap(), c[2].parse().unwrap())
    }
}

#[derive(Debug, Error)]
pub enum AdvErr {
    #[error("Failed to parse CVE identifier `{}'", id)]
    ParseCVE { id: String },
}

impl FromStr for Advisory {
    type Err = AdvErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if CVESPEC.is_match(s) {
            Ok(Self(s.into()))
        } else {
            Err(AdvErr::ParseCVE { id: s.to_owned() })
        }
    }
}

impl TryFrom<String> for Advisory {
    type Error = AdvErr;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&s)
    }
}

impl fmt::Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Ord for Advisory {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_tuple().cmp(&other.as_tuple())
    }
}

impl PartialOrd for Advisory {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    fn cve(y: u16, n: u64) -> Advisory {
        Advisory(format!("CVE-{}-{:04}", y, n).into())
    }

    #[test]
    fn fmt_cve() {
        assert_eq!(cve(2019, 544).to_string(), "CVE-2019-0544");
        assert_eq!(cve(2019, 3544).to_string(), "CVE-2019-3544");
        assert_eq!(cve(2019, 1003544).to_string(), "CVE-2019-1003544");
    }

    #[test]
    fn parse_cve() {
        assert_eq!(
            "CVE-2019-20484"
                .parse::<Advisory>()
                .expect("no parse error"),
            cve(2019, 20484)
        );
    }

    #[test]
    fn parse_invalid_cves() {
        assert_matches!("".parse::<Advisory>(), Err(AdvErr::ParseCVE { .. }));
        assert_matches!("foo".parse::<Advisory>(), Err(AdvErr::ParseCVE { .. }));
        assert_matches!("CVE-20".parse::<Advisory>(), Err(AdvErr::ParseCVE { .. }));
        assert_matches!("CVE-20-1".parse::<Advisory>(), Err(AdvErr::ParseCVE { .. }));
        assert_matches!(
            "CVE-2014-".parse::<Advisory>(),
            Err(AdvErr::ParseCVE { .. })
        );
    }

    #[test]
    fn ordering() {
        assert!(cve(2019, 9999) < cve(2019, 10000));
    }
}
