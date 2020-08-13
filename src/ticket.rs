use crate::advisory::Advisory;
use crate::package::{Maintainer, Package};
use crate::scan::{Branch, ScanByBranch, ScoreMap};

use colored::*;
use ordered_float::OrderedFloat;
use smol_str::SmolStr;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::format_args;
use std::fs;
use std::io::BufWriter;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Abstract ticket/issue representation.
///
/// This will be picked up by tracker/* to create a concrete issue.
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
        write!(BufWriter::new(fs::File::create(file_name)?), "{:#}", self)?;
        Ok(())
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
        writeln!(f, "\nScanned versions: {}.\n", relevant.join("; "))?;
        for m in &self.maintainers {
            writeln!(f, "Cc @{}", m)?;
        }
        if let Some(url) = &self.issue_url {
            writeln!(f, "<!-- {} -->", url)?;
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
        Ordering::Equal => a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal),
    }
}

/// One ticket per package, containing scan results for all branches
pub fn ticket_list(iteration: u32, scan_res: ScanByBranch, ping_maintainers: bool) -> Vec<Ticket> {
    let mut scores = ScoreMap::default();
    let mut maintmap: HashMap<Package, Vec<Maintainer>> = HashMap::new();
    // Step 1: for each pkg, list all pairs (advisory, branch) in random order
    let mut pkgmap: HashMap<Package, Vec<(Advisory, Branch)>> = HashMap::new();
    for (branch, scan_results) in scan_res {
        for res in scan_results {
            if ping_maintainers {
                if let Some(e) = maintmap.get_mut(&res.pkg) {
                    e.extend(res.maintainers);
                } else {
                    maintmap.insert(res.pkg.clone(), res.maintainers.clone());
                }
            }
            let e = pkgmap.entry(res.pkg).or_insert_with(Vec::new);
            e.extend(res.affected_by.into_iter().map(|adv| (adv, branch.clone())));
            scores.extend(res.cvssv3_basescore);
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
                t.affected
                    .entry(advisory)
                    .or_insert_with(|| Detail::new(score.cloned()))
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

#[derive(Debug, Default)]
pub struct Applicable {
    known: HashSet<SmolStr>,
}

impl Applicable {
    fn from_store_path(sp: &str) -> Option<&str> {
        let sp = sp.trim();
        match sp.len() {
            0 => None,
            x if x > 44 && &sp[43..44] == "-" => Some(&sp[44..]),
            x if x > 33 && &sp[32..33] == "-" => Some(&sp[33..]),
            _ => Some(sp),
        }
    }

    fn extract_derivations(storedump: &str) -> impl Iterator<Item = SmolStr> + '_ {
        static STRIP_OUTPUTS: &[&str] = &["-dev", "-bin", "-out", "-lib", "-ga"];
        storedump.lines().filter_map(|line| {
            if let Some(deriv) = Self::from_store_path(line) {
                for suffix in STRIP_OUTPUTS {
                    if deriv.ends_with(suffix) {
                        return Some(SmolStr::new(&deriv[..(deriv.len() - suffix.len())]));
                    }
                }
                Some(SmolStr::new(deriv))
            } else {
                None
            }
        })
    }

    pub fn new(dir: &Path) -> Result<Self, io::Error> {
        let mut known: HashSet<SmolStr> = HashSet::new();
        for entry in fs::read_dir(dir)? {
            let e = entry?;
            if e.file_type()?.is_file() && &e.file_name().to_string_lossy()[0..1] != "." {
                known.extend(Self::extract_derivations(&fs::read_to_string(&e.path())?))
            }
        }
        Ok(Self { known })
    }

    pub fn filter(&self, mut tickets: Vec<Ticket>) -> Vec<Ticket> {
        tickets.retain(|t| self.known.contains(t.pkg.as_str()));
        tickets
    }
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use crate::scan::VulnixRes;
    use crate::tests::{adv, br, create_branches, pkg};

    use maplit::hashmap;
    use tempfile::TempDir;

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
            ticket_list(1, scan, false),
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
                ..VulnixRes::default()
            }],
            Branch::new("br2") => vec![VulnixRes {
                pkg: pkg("libtiff-4.0.9"),
                affected_by: vec![adv("CVE-2018-17101")],
                cvssv3_basescore: hashmap! { adv("CVE-2018-17101") => 8.7 },
                ..VulnixRes::default()
            }],
        };
        assert_eq!(
            ticket_list(2, scan, false),
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
        let out = format!("{:#}", tkt);
        println!("{}", out);
        assert_eq!(
            out,
            "\
Vulnerability roundup 2: libtiff-4.0.9: 3 advisories [8.8]\n\
\n\
[search](https://search.nix.gsc.io/?q=libtiff&i=fosho&repos=NixOS-nixpkgs), \
[files](https://github.com/NixOS/nixpkgs/search?utf8=%E2%9C%93&q=libtiff+in%3Apath&type=Code)\n\
\n\
* [ ] [CVE-2018-17101](https://nvd.nist.gov/vuln/detail/CVE-2018-17101) CVSSv3=8.8 (br0, br1)\n\
* [ ] [CVE-2018-17100](https://nvd.nist.gov/vuln/detail/CVE-2018-17100) CVSSv3=8.7 (br0)\n\
* [ ] [CVE-2018-17000](https://nvd.nist.gov/vuln/detail/CVE-2018-17000) (br0)\n\
\n\
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
            affected: hashmap! { adv("CVE-2018-17000") => det_br(&[&b], None) },
            maintainers: vec!["ericson2314".into()],
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
            affected: hashmap! {adv("CVE-2018-17100") => det_br(&[&br[0]], Some(8.8))},
            ..Ticket::default()
        };
        assert!(
            tkt.to_string()
                .contains("versions: nixos-18.09: 5d4a1a3897e"),
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

    #[test]
    fn applicable_should_contain_derivations() {
        let a = Applicable::new(&Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/storepaths"))
            .expect("failed to create Applicable instance");
        assert!(a.known.contains("zsh-5.7.1")); // from vm4
        assert!(a.known.contains("nspr-4.21")); // from vm5
        assert!(a.known.contains("nodejs-8.15.1")); // from vm9
    }

    #[test]
    fn filter_relevant() {
        let td = TempDir::new().unwrap();
        // libtiff-4.0.8 is not present on any vm
        let t1 = Ticket {
            pkg: pkg("libtiff-4.0.8"),
            ..Ticket::default()
        };
        let res = Applicable::new(td.path()).unwrap().filter(vec![t1.clone()]);
        assert_eq!(res, vec![]);

        // net-snmp-5.8 is present on vm4 (without prefix)
        let t2 = Ticket {
            pkg: pkg("net-snmp-5.8"),
            ..Ticket::default()
        };
        // boehm-gc-8.0.2 is present on vm5 (with Nix hash prefix)
        let t3 = Ticket {
            pkg: pkg("boehm-gc-8.0.2"),
            ..Ticket::default()
        };
        // gdbm-1.18.1 is present on vm9 (with full Nix store prefix)
        let t4 = Ticket {
            pkg: pkg("gdbm-1.18.1"),
            ..Ticket::default()
        };
        let a = Applicable::new(&Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/storepaths"))
            .expect("failed to create Applicable instance");
        let res = a.filter([&t1, &t2, &t3, &t4].iter().map(|&t| t.clone()).collect());
        assert_eq!(res, vec![t2.clone(), t3.clone(), t4.clone()]);
    }

    #[test]
    fn strip_output_suffix() {
        let storedump = "\
w43m4jsawvibjx5r20rx26h19hxkq5dg-db-5.3.28-bin
/nix/store/1yqbpsfyqcamlr79jzsh1cpd2pkv1858-unbound-1.9.0-lib
util-linux-2.33.1-dev
zsh-5.7.1
        ";
        let derivs: Vec<_> = Applicable::extract_derivations(storedump).collect();
        assert_eq!(
            vec![
                "db-5.3.28",
                "unbound-1.9.0",
                "util-linux-2.33.1",
                "zsh-5.7.1"
            ],
            derivs
        );
    }
}
