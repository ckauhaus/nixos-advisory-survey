use crate::advisory::Advisory;
use crate::package::{Maintainer, Package};
use crate::scan::{Branch, MaintByBranch, ScanByBranch, ScoreMap};

use colored::*;
use ordered_float::OrderedFloat;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::format_args;
use std::fs;
use std::io::BufWriter;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Ticket {
    pub iteration: u32,
    pub pkg: Package,
    pub affected: HashMap<Advisory, Detail>,
    pub issue_id: Option<u64>,
    pub issue_url: Option<String>,
    pub maintainers: Vec<Maintainer>,
}

impl Ticket {
    /// Creates a new Ticket with empty 'affected' list.
    pub fn new(iteration: u32, pkg: Package) -> Self {
        Self {
            iteration,
            pkg,
            ..Self::default()
        }
    }

    /// Local file name (excluding directory)
    pub fn file_name(&self) -> PathBuf {
        PathBuf::from(format!("ticket.{}.md", self.pkg.name))
    }

    /// Package name + version
    pub fn name(&self) -> &str {
        &self.pkg.name
    }

    /// Package name without version
    pub fn pname(&self) -> &str {
        &self.pkg.pname()
    }

    /// Writes ticket to disk, optionally with a pointer to a tracker issue
    pub fn write<P: AsRef<Path>>(&self, file_name: P) -> io::Result<()> {
        let inum = match self.issue_id {
            Some(id) => format!("issue #{}, ", id.to_string().green()),
            None => "".to_owned(),
        };
        info!(
            "{}: {}file {}",
            self.name().yellow(),
            inum,
            self.file_name().to_string_lossy().green()
        );
        let mut f = BufWriter::new(fs::File::create(file_name)?);
        write!(f, "{:#}", self)?;
        Ok(())
    }

    /// Ticket headline
    pub fn summary(&self) -> String {
        let num = self.affected.len();
        let advisory = if num == 1 { "advisory" } else { "advisories" };
        format!(
            "Vulnerability roundup {}: {}: {} {}",
            self.iteration, self.pkg.name, num, advisory
        )
    }

    /// Maximum CVSS score over listed CVEs
    pub fn max_score(&self) -> Option<OrderedFloat<f32>> {
        self.affected.values().filter_map(|d| d.score).max()
    }
}

impl fmt::Display for Ticket {
    /// Normal Display: only ticket body
    /// Alternate Display: headline + body
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            writeln!(f, "{}\n", self.summary())?;
        }
        writeln!(
            f,
            "\
[search](https://search.nix.gsc.io/?q={pname}&i=fosho&repos=NixOS-nixpkgs), \
[files](https://github.com/NixOS/nixpkgs/search?utf8=%E2%9C%93&q={pname}+in%3Apath&type=Code)\n\
        ",
            pname = self.pname()
        )?;
        let mut adv: Vec<(&Advisory, &Detail)> = self.affected.iter().collect();
        adv.sort_unstable_by(cmp_score);
        for (advisory, details) in adv {
            writeln!(
                f,
                "* [ ] [{adv}](https://nvd.nist.gov/vuln/detail/{adv}) {details}",
                adv = advisory,
                details = details
            )?;
        }
        let mut relevant: Vec<String> = self
            .affected
            .values()
            .flat_map(|d| d.branches.iter())
            .map(|b| format!("{}: {}", b.name.as_str(), &b.rev.as_str()[..11]))
            .collect();
        relevant.sort();
        relevant.dedup();
        writeln!(
            f,
            "\nScanned versions: {}. May contain false positives.",
            relevant.join("; ")
        )?;
        if !self.maintainers.is_empty() {
            writeln!(f, "\nCc {}", self.maintainers.join(", "))?;
        }
        for url in &self.issue_url {
            writeln!(f, "\n<!-- {} -->", url)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, PartialOrd)]
pub struct Detail {
    branches: Vec<Branch>,
    score: Option<OrderedFloat<f32>>,
}

impl Detail {
    fn new(score: Option<f32>) -> Self {
        Self {
            score: score.map(|s| OrderedFloat(s)),
            ..Default::default()
        }
    }

    fn add(&mut self, branch: Branch) {
        self.branches.push(branch);
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(score) = self.score {
            write!(f, "CVSSv3={:1.1} ", score)?;
        }
        let b: Vec<&str> = self.branches.iter().map(|b| b.name.as_str()).collect();
        write!(f, "({})", b.join(", "))
    }
}

fn cmp_score(a: &(&Advisory, &Detail), b: &(&Advisory, &Detail)) -> Ordering {
    let left = a.1.score.unwrap_or(OrderedFloat(-1.0));
    let right = b.1.score.unwrap_or(OrderedFloat(-1.0));
    match left.cmp(&right) {
        Ordering::Greater => Ordering::Less,
        Ordering::Less => Ordering::Greater,
        Ordering::Equal => a.0.cmp(&b.0),
    }
}

/// One ticket per package, containing scan results for all branches
pub fn ticket_list(
    iteration: u32,
    scan_res: ScanByBranch,
    maintainers: MaintByBranch,
) -> Vec<Ticket> {
    let mut scores = ScoreMap::default();
    // Step 1: for each pkgs, list all pairs (advisory, branch) in random order
    let mut pkgmap: HashMap<Package, Vec<(Advisory, Branch)>> = HashMap::new();
    for (branch, scan_results) in scan_res {
        for res in scan_results {
            let e = pkgmap.entry(res.pkg).or_insert_with(Vec::new);
            e.extend(res.affected_by.into_iter().map(|adv| (adv, branch.clone())));
            scores.extend(&res.cvssv3_basescore);
        }
    }
    // XXX Step 2: consolidate maintainers
    // Step 3: consolidate branches
    let mut tickets: Vec<Ticket> = pkgmap
        .into_iter()
        .map(|(pkg, mut adv)| {
            adv.sort(); // especially needed to get branch ordering right
            let mut t = Ticket::new(iteration, pkg);
            for (advisory, branch) in adv {
                let score = scores.get(&advisory);
                t.affected
                    .entry(advisory)
                    .or_insert_with(|| Detail::new(score.cloned()))
                    .add(branch)
            }
            t
        })
        .collect();
    tickets.sort_by(|a, b| a.pkg.cmp(&b.pkg));
    tickets
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use crate::scan::VulnixRes;
    use crate::tests::{adv, create_branches, pkg};
    use maplit::hashmap;

    /// Helpers for quick construction of Detail structs
    fn det(branches: &[&str], score: Option<f32>) -> Detail {
        Detail {
            branches: branches.iter().map(|&b| Branch::new(b)).collect(),
            ..Detail::new(score)
        }
    }

    fn det_br(branches: &[&Branch], score: Option<f32>) -> Detail {
        Detail {
            branches: branches.iter().map(|&b| b.clone()).collect(),
            ..Detail::new(score)
        }
    }

    fn nomaint() -> MaintByBranch {
        MaintByBranch::default()
    }

    #[test]
    fn decode_scan_single_branch() {
        let scan = hashmap! {
            Branch::new("br1") => vec![
                VulnixRes {
                    pkg: pkg("ncurses-6.1"),
                    affected_by: vec![adv("CVE-2018-10754")],
                    .. Default::default()
                },
                VulnixRes {
                    pkg: pkg("libtiff-4.0.9"),
                    affected_by: vec![
                        adv("CVE-2018-17000"),
                        adv("CVE-2018-17100"),
                        adv("CVE-2018-17101")],
                    .. Default::default()
                },
            ]
        };
        assert_eq!(
            ticket_list(1, scan, nomaint()),
            &[
                Ticket {
                    iteration: 1,
                    pkg: pkg("libtiff-4.0.9"),
                    affected: hashmap! {
                        adv("CVE-2018-17000") => det(&["br1"], None),
                        adv("CVE-2018-17100") => det(&["br1"], None),
                        adv("CVE-2018-17101") => det(&["br1"], None),
                    },
                    ..Ticket::default()
                },
                Ticket {
                    iteration: 1,
                    pkg: pkg("ncurses-6.1"),
                    affected: hashmap! { adv("CVE-2018-10754") => det(&["br1"], None) },
                    ..Ticket::default()
                }
            ]
        );
    }

    #[test]
    fn decode_scan_multiple_branches() {
        let scan = hashmap! {
            Branch::new("br1") => vec![VulnixRes {
                pkg: pkg("libtiff-4.0.9"),
                affected_by: vec![adv("CVE-2018-17100"), adv("CVE-2018-17101")],
                cvssv3_basescore: hashmap! {
                    adv("CVE-2018-17100") => 8.8,
                    adv("CVE-2018-17101") => 8.7,
                },
            }],
            Branch::new("br2") => vec![VulnixRes {
                pkg: pkg("libtiff-4.0.9"),
                affected_by: vec![adv("CVE-2018-17101")],
                cvssv3_basescore: hashmap! { adv("CVE-2018-17101") => 8.7 }
            }],
        };
        assert_eq!(
            ticket_list(2, scan, nomaint()),
            &[Ticket {
                iteration: 2,
                pkg: pkg("libtiff-4.0.9"),
                affected: hashmap! {
                    adv("CVE-2018-17100") => det(&["br1"], Some(8.8)),
                    adv("CVE-2018-17101") => det(&["br1", "br2"], Some(8.7)),
                },
                ..Ticket::default()
            }]
        );
    }

    #[test]
    fn rendered_ticket() {
        let br = create_branches(&[
            "br0=5d4a1a3897e2d674522bcb3aa0026c9e32d8fd7c",
            "br1=80738ed9dc0ce48d7796baed5364eef8072c794d",
        ]);
        let tkt = Ticket {
            iteration: 2,
            pkg: pkg("libtiff-4.0.9"),
            affected: hashmap! {
                adv("CVE-2018-17000") => det_br(&[&br[0]], None),
                adv("CVE-2018-17100") => det_br(&[&br[0]], Some(8.7)),
                adv("CVE-2018-17101") => det_br(&[&br[0], &br[1]], Some(8.8)),
            },
            ..Ticket::default()
        };
        // should be sorted by score in decreasing order, undefined scores last
        assert_eq!(
            format!("{:#}", tkt),
            "\
Vulnerability roundup 2: libtiff-4.0.9: 3 advisories\n\
\n\
[search](https://search.nix.gsc.io/?q=libtiff&i=fosho&repos=NixOS-nixpkgs), \
[files](https://github.com/NixOS/nixpkgs/search?utf8=%E2%9C%93&q=libtiff+in%3Apath&type=Code)\n\
\n\
* [ ] [CVE-2018-17101](https://nvd.nist.gov/vuln/detail/CVE-2018-17101) CVSSv3=8.8 (br0, br1)\n\
* [ ] [CVE-2018-17100](https://nvd.nist.gov/vuln/detail/CVE-2018-17100) CVSSv3=8.7 (br0)\n\
* [ ] [CVE-2018-17000](https://nvd.nist.gov/vuln/detail/CVE-2018-17000) (br0)\n\
\n\
Scanned versions: br0: 5d4a1a3897e; br1: 80738ed9dc0. \
May contain false positives.\n\
        "
        );
    }

    #[test]
    fn print_only_relevant_branches() {
        let br = create_branches(&[
            "nixos-18.09=5d4a1a3897e2d674522bcb3aa0026c9e32d8fd7c",
            "nixos-unstable=80738ed9dc0ce48d7796baed5364eef8072c794d",
        ]);
        let tkt = Ticket {
            iteration: 1,
            pkg: pkg("libtiff-4.0.9"),
            affected: hashmap! { adv("CVE-2018-17100") => det_br(&[&br[0]], Some(8.8)) },
            ..Ticket::default()
        };
        assert!(
            tkt.to_string()
                .contains("versions: nixos-18.09: 5d4a1a3897e. May"),
            format!("branch summary not correct:\n{}", tkt)
        );
    }

    #[test]
    fn cmp_score_ordering() {
        assert_eq!(
            cmp_score(
                &(&adv("CVE-2019-0001"), &det(&[], Some(5.1))),
                &(&adv("CVE-2019-0001"), &det(&[], Some(5.1)))
            ),
            Ordering::Equal
        );
        assert_eq!(
            cmp_score(
                &(&adv("CVE-2019-0001"), &det(&[], Some(5.0))),
                &(&adv("CVE-2019-0001"), &det(&[], Some(5.1)))
            ),
            Ordering::Greater
        );
        assert_eq!(
            cmp_score(
                &(&adv("CVE-2019-0001"), &det(&[], Some(0.0))),
                &(&adv("CVE-2019-0001"), &det(&[], None))
            ),
            Ordering::Less
        );
        assert_eq!(
            cmp_score(
                &(&adv("CVE-2019-10000"), &det(&[], Some(5.5))),
                &(&adv("CVE-2019-9999"), &det(&[], Some(5.5)))
            ),
            Ordering::Greater
        );
    }

    #[test]
    fn max_score() {
        let tkt = Ticket {
            affected: hashmap! { adv("CVE-2018-17100") => det(&[], None) },
            ..Ticket::default()
        };
        assert!(tkt.max_score().is_none());

        let tkt = Ticket {
            affected: hashmap! {
                adv("CVE-2018-17100") => det(&[], None),
                adv("CVE-2020-12755") => det(&[], Some(3.3)),
                adv("CVE-2020-12767") => det(&[], Some(9.8)),
            },
            ..Ticket::default()
        };
        assert_eq!(tkt.max_score().unwrap().into_inner(), 9.8);
    }
}
