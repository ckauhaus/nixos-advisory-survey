use crate::advisory::Advisory;
use crate::branches::{Branch, ScanByBranch};
use crate::scan::ScoreMap;
use crate::source::{maintainer_contacts, Maintainer, Package};

use ordered_float::OrderedFloat;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

/// Abstract ticket/issue representation.
///
/// This will be picked up by tracker/* to create a concrete issue.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Ticket {
    pub iteration: u32,
    pub pkg: Package,
    pub affected: HashMap<Advisory, Detail>,
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

    /// Package name + version
    pub fn name(&self) -> &str {
        &self.pkg.name
    }

    /// Package name without version
    pub fn pname(&self) -> &str {
        self.pkg.pname()
    }

    /// Ticket headline
    pub fn summary(&self) -> String {
        let num = self.affected.len();
        let advisory = if num == 1 { "advisory" } else { "advisories" };
        let max_cvss = self
            .max_score()
            .map(|s| format!(" [{:.1}]", s))
            .unwrap_or_default();
        format!(
            "Vulnerability roundup {}: {}: {} {}{}",
            self.iteration, self.pkg.name, num, advisory, max_cvss
        )
    }

    /// Maximum CVSS score over listed CVEs
    pub fn max_score(&self) -> Option<OrderedFloat<f32>> {
        self.affected.values().filter_map(|d| d.score).max()
    }

    pub fn render<W: fmt::Write>(&self, f: &mut W, notify: bool) -> fmt::Result {
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
        for (advisory, detail) in &adv {
            writeln!(
                f,
                "* [ ] [{adv}](https://nvd.nist.gov/vuln/detail/{adv}) {detail}",
                adv = advisory,
                detail = detail
            )?;
        }
        if adv.iter().any(|(_, d)| d.description.is_some()) {
            writeln!(f, "\n## CVE details")?;
        }
        for (adv, detail) in &adv {
            if let Some(ref desc) = detail.description {
                writeln!(f, "\n### {adv}\n\n{desc}", adv = adv, desc = desc)?;
            }
        }
        let mut relevant: Vec<String> = self
            .affected
            .values()
            .flat_map(|d| d.branches.iter())
            .map(|b| format!("{}: {}", b.name.as_str(), &b.rev.as_str()[..11]))
            .collect();
        relevant.sort();
        relevant.dedup();
        writeln!(f, "\n-----\nScanned versions: {}.\n", relevant.join("; "))?;
        if notify {
            for contact in maintainer_contacts(&self.maintainers) {
                writeln!(f, "Cc @{}", contact)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Ticket {
    /// Normal Display: only ticket body
    /// Alternate Display: headline + body
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            writeln!(f, "# {}\n", self.summary())?;
            self.render(f, true)
        } else {
            self.render(f, false)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, PartialOrd, Serialize)]
pub struct Detail {
    branches: Vec<Branch>,
    score: Option<OrderedFloat<f32>>,
    description: Option<String>,
}

impl Detail {
    fn new(score: Option<f32>, description: Option<String>) -> Self {
        Self {
            score: score.map(OrderedFloat),
            description,
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
        Ordering::Equal => a.0.partial_cmp(b.0).unwrap_or(Ordering::Equal),
    }
}

/// One ticket per package, containing scan results for all branches
pub fn ticket_list(iteration: u32, scan_res: ScanByBranch) -> Vec<Ticket> {
    let mut scores = ScoreMap::default();
    // Maintainership may change across branches. Collect & notify all maintainers.
    let mut maintmap: HashMap<Package, Vec<Maintainer>> = HashMap::new();
    let mut descmap: HashMap<Advisory, String> = HashMap::new();
    // Step 1: for each pkg, record all pairs (advisory, branch)
    let mut pkgmap: HashMap<Package, Vec<(Advisory, Branch)>> = HashMap::new();
    for (branch, vulnix_res) in scan_res {
        for res in vulnix_res {
            let m = maintmap.entry(res.pkg.clone()).or_insert_with(Vec::new);
            m.extend(res.maintainers);
            let p = pkgmap.entry(res.pkg).or_insert_with(Vec::new);
            p.extend(res.affected_by.into_iter().map(|adv| (adv, branch.clone())));
            scores.extend(res.cvssv3_basescore);
            descmap.extend(res.description.into_iter());
        }
    }
    // Step 2: consolidate branches
    let mut tickets: Vec<Ticket> = pkgmap
        .into_iter()
        .map(|(pkg, mut advbr)| {
            advbr.sort_unstable();
            let mut t = Ticket::new(iteration, pkg);
            for (advisory, branch) in advbr {
                let score = scores.get(&advisory);
                let desc = descmap.get(&advisory).map(|d| d.to_owned());
                t.affected
                    .entry(advisory)
                    .or_insert_with(|| Detail::new(score.cloned(), desc))
                    .add(branch)
            }
            if let Some(maintainers) = maintmap.remove(&t.pkg) {
                t.maintainers = maintainers;
                t.maintainers.sort();
                t.maintainers.dedup();
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
    use crate::tests::{adv, br, create_branches, pkg};

    use maplit::{btreemap, hashmap};

    /// Helpers for quick construction of Detail structs
    fn det(branches: &[&str], score: Option<f32>) -> Detail {
        Detail {
            branches: branches.iter().map(|&b| Branch::new(b)).collect(),
            ..Detail::new(score, None)
        }
    }

    fn det_br(branches: &[&Branch], score: Option<f32>, desc: Option<String>) -> Detail {
        Detail {
            branches: branches.iter().map(|&b| b.clone()).collect(),
            ..Detail::new(score, desc)
        }
    }

    #[test]
    fn decode_scan_single_branch() {
        let scan = hashmap! {
            Branch::new("br1") => vec![
                VulnixRes::new(pkg("ncurses-6.1"), vec![adv("CVE-2018-10754")]),
                VulnixRes::new(pkg("libtiff-4.0.9"), vec![
                    adv("CVE-2018-17000"), adv("CVE-2018-17100"), adv("CVE-2018-17101")])
            ]
        };
        assert_eq!(
            ticket_list(1, scan),
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
                cvssv3_basescore: btreemap! {
                    adv("CVE-2018-17100") => 8.8,
                    adv("CVE-2018-17101") => 8.7,
                },
                ..VulnixRes::default()
            }],
            Branch::new("br2") => vec![VulnixRes {
                pkg: pkg("libtiff-4.0.9"),
                affected_by: vec![adv("CVE-2018-17101")],
                cvssv3_basescore: btreemap! { adv("CVE-2018-17101") => 8.7 },
                ..VulnixRes::default()
            }],
        };
        assert_eq!(
            ticket_list(2, scan),
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
                adv("CVE-2018-17000") => det_br(&[&br[0]], None, None),
                adv("CVE-2018-17100") => det_br(&[&br[0]], Some(8.7), Some("Detail 17100".into())),
                adv("CVE-2018-17101") => det_br(&[&br[0], &br[1]], Some(8.8), Some("Detail 17101".into())),
            },
            ..Ticket::default()
        };
        // should be sorted by score in decreasing order, undefined scores last
        let out = format!("{:#}", tkt);
        println!("{}", out);
        assert_eq!(
            out,
            "\
# Vulnerability roundup 2: libtiff-4.0.9: 3 advisories [8.8]\n\
\n\
[search](https://search.nix.gsc.io/?q=libtiff&i=fosho&repos=NixOS-nixpkgs), \
[files](https://github.com/NixOS/nixpkgs/search?utf8=%E2%9C%93&q=libtiff+in%3Apath&type=Code)\n\
\n\
* [ ] [CVE-2018-17101](https://nvd.nist.gov/vuln/detail/CVE-2018-17101) CVSSv3=8.8 (br0, br1)\n\
* [ ] [CVE-2018-17100](https://nvd.nist.gov/vuln/detail/CVE-2018-17100) CVSSv3=8.7 (br0)\n\
* [ ] [CVE-2018-17000](https://nvd.nist.gov/vuln/detail/CVE-2018-17000) (br0)\n\
\n\
## CVE details\n\
\n\
### CVE-2018-17101
\n\
Detail 17101\n\
\n\
### CVE-2018-17100
\n\
Detail 17100\n\
\n\
-----\n\
Scanned versions: br0: 5d4a1a3897e; br1: 80738ed9dc0.\n\n\
        "
        );
    }

    #[test]
    fn render_ticket_ping_maintainers() {
        let b = br("branch0=80738ed9dc0ce48d7796baed5364eef8072c794d");
        let tkt = Ticket {
            iteration: 3,
            pkg: pkg("libtiff-4.0.9"),
            affected: hashmap! { adv("CVE-2018-17000") => det_br(&[&b], None, None) },
            maintainers: vec![Maintainer::new("ericson2314")],
            ..Ticket::default()
        };
        // should be sorted by score in decreasing order, undefined scores last
        let out = format!("{:#}", tkt);
        println!("{}", out);
        assert!(out.contains("Cc @ericson2314"));
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
            affected: hashmap! {adv("CVE-2018-17100") => det_br(&[&br[0]], Some(8.8), None)},
            ..Ticket::default()
        };
        assert!(
            tkt.to_string()
                .contains("versions: nixos-18.09: 5d4a1a3897e"),
            "branch summary not correct:\n{}",
            tkt
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
