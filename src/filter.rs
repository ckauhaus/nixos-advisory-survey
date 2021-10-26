use crate::source::NixEnvPkg;

use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

fn extract_derivations(storelisting: &str) -> impl Iterator<Item = String> + '_ {
    storelisting.lines().filter_map(|sp| {
        let sp = sp.trim();
        match sp.len() {
            0 => None,
            // /nix/store/HASH-name
            x if x > 44 && &sp[43..44] == "-" => Some(String::from(&sp[44..])),
            // HASH-name
            x if x > 33 && &sp[32..33] == "-" => Some(String::from(&sp[33..])),
            // just name
            _ => Some(String::from(sp)),
        }
    })
}

pub struct StoreContents {
    known: HashSet<String>,
}

impl StoreContents {
    pub fn from_dir(dir: &Path) -> Result<Self> {
        let mut known = HashSet::new();
        for entry in fs::read_dir(dir)? {
            let e = entry?;
            if e.file_type()?.is_file() && !e.file_name().to_string_lossy().starts_with('.') {
                known.extend(extract_derivations(&fs::read_to_string(&e.path())?))
            }
        }
        Ok(Self { known })
    }

    pub fn is_installed(&self, pi: &NixEnvPkg) -> bool {
        if self.known.contains(pi.pkg.as_str()) {
            return true;
        }
        pi.meta
            .outputs
            .iter()
            .any(|out| self.known.contains(&format!("{}-{}", pi.pkg, out)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::source::{NixEnvPkg, Package, PkgMeta};

    use std::str::FromStr;

    type Str = smol_str::SmolStr;

    #[test]
    fn should_contain_derivations() {
        let a = StoreContents::from_dir(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/storepaths"),
        )
        .expect("failed to create StoreContents instance");
        assert!(a.known.contains("zsh-5.7.1")); // from vm4
        assert!(a.known.contains("nspr-4.21")); // from vm5
        assert!(a.known.contains("nodejs-8.15.1")); // from vm9
    }

    fn nixenvpkg(name: &str, outputs: &[&str]) -> NixEnvPkg {
        let pkg = Package::from_str(name).unwrap();
        NixEnvPkg {
            pkg: pkg.name.clone(),
            meta: PkgMeta {
                outputs: outputs.iter().map(|s| Str::from(*s)).collect(),
                ..PkgMeta::default()
            },
            ..NixEnvPkg::default()
        }
    }

    #[test]
    fn filter_installed() {
        let stores = StoreContents::from_dir(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/storepaths"),
        )
        .unwrap();
        // libtiff-4.0.8 is not present on any vm
        assert!(!stores.is_installed(&nixenvpkg("libtiff-4.0.8", &[])));
        // wdiff does neither declare nor install multiple outputs
        assert!(stores.is_installed(&nixenvpkg("wdiff-1.2.2", &[])));
        // the "bin" output is installed, but not declared here -> should fail
        assert!(!stores.is_installed(&nixenvpkg("bzip2-1.0.6.0.1", &[])));
        // "bin" output properly declared
        assert!(stores.is_installed(&nixenvpkg("bzip2-1.0.6.0.1", &["bin"])));
        // outputs declared but unused
        assert!(stores.is_installed(&nixenvpkg("nspr-4.21", &["out", "lib"])));
    }
}
