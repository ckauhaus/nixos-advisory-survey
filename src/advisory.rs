use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize, Serializer};
use std::cmp::{Ord, Ordering, PartialOrd};
use std::convert::TryFrom;
use std::fmt;
use std::io::{Cursor, Write};
use std::str::FromStr;
use thiserror::Error;

type Result<T, E = AdvErr> = std::result::Result<T, E>;

lazy_static! {
    static ref CVESPEC: Regex = Regex::new(r"^CVE-(\d{4})-(\d+)$").unwrap();
}

/// Securty advisory identifier. Currently only CVEs are supported.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Advisory(u16, u64);

impl Advisory {
    #[allow(unused)]
    pub fn new(year: u16, id: u64) -> Self {
        Self(year, id)
    }

    /// Represent myself as numeric tuple if possible. This is needed for sorting CVEs.
    pub fn as_tuple(&self) -> (u16, u64) {
        // let c = ;
        // (c[1].parse().unwrap(), c[2].parse().unwrap())
        (self.0, self.1)
    }
}

#[derive(Debug, Error)]
pub enum AdvErr {
    #[error("Failed to parse CVE identifier `{}'", 0)]
    ParseCVE(String),
}

impl FromStr for Advisory {
    type Err = AdvErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let c = CVESPEC.captures(s).ok_or(AdvErr::ParseCVE(s.into()))?;
        match (c[1].parse(), c[2].parse()) {
            (Ok(year), Ok(id)) => Ok(Self(year, id)),
            _ => Err(AdvErr::ParseCVE(s.into())),
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
        write!(f, "CVE-{}-{:04}", self.0, self.1)
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

impl Serialize for Advisory {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut buf = [0u8; 32];
        let mut buf = Cursor::new(&mut buf[..]);
        buf.write_fmt(format_args!("CVE-{}-{:04}", self.0, self.1))
            .expect("BUG: CVE serialize: value too long");
        unsafe {
            ser.serialize_str(std::str::from_utf8_unchecked(
                &buf.get_ref()[..buf.position() as usize],
            ))
        }
    }
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    fn cve(y: u16, n: u64) -> Advisory {
        Advisory::new(y, n)
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
            "CVE-2019-20484".parse::<Advisory>().expect("parse error"),
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

    #[test]
    fn serialize() {
        assert_eq!(
            serde_json::to_string(&Advisory::new(2021, 134)).unwrap(),
            "\"CVE-2021-0134\""
        );
    }

    #[test]
    fn deserialize() {
        assert_eq!(
            serde_json::from_str::<Advisory>("\"CVE-2021-12345\"").unwrap(),
            Advisory::new(2021, 12345)
        );
    }
}
