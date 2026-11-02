//! Device manufacturers from the IEEE OUI registry (MA-L), downloaded by
//! `tools/dev/fetch-oui.ps1` to `data\oui\oui.csv`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "oui.csv";

#[derive(Default)]
pub struct Vendors(HashMap<[u8; 3], String>);

/// One CSV line's fields, with quotes ("…", and "" inside them).
fn fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut field)),
            c => field.push(c),
        }
    }
    out.push(field);
    out
}

fn prefix(hex: &str) -> Option<[u8; 3]> {
    let digits: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
    if digits.len() < 6 {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&digits[i..i + 2], 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

impl Vendors {
    /// The registry CSV: "Registry,Assignment,Organization Name,Organization Address".
    pub fn parse(text: &str) -> Vendors {
        let mut map = HashMap::new();
        for line in text.lines().skip(1) {
            let f = fields(line);
            if f.len() >= 3
                && f[0] == "MA-L"
                && let Some(p) = prefix(&f[1])
            {
                map.insert(p, f[2].trim().to_string());
            }
        }
        Vendors(map)
    }

    pub fn load(path: &Path) -> Option<Vendors> {
        let text = std::fs::read_to_string(path).ok()?;
        let v = Vendors::parse(&text);
        (!v.0.is_empty()).then_some(v)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The manufacturer for a hardware address ("aa-bb-cc-…"), if registered.
    /// Random (private) addresses have none.
    pub fn lookup(&self, mac: &str) -> Option<String> {
        if randomized(mac) {
            return None;
        }
        self.0.get(&prefix(mac)?).cloned()
    }
}

/// A locally administered (random, private) address, as phones and laptops
/// use per network: the second bit of the first byte is set.
pub fn randomized(mac: &str) -> bool {
    prefix(mac).is_some_and(|p| p[0] & 0b10 != 0)
}

/// One device's address, not a broadcast or multicast group's (the first
/// byte's lowest bit is clear).
pub fn unicast(mac: &str) -> bool {
    prefix(mac).is_some_and(|p| p[0] & 1 == 0)
}

/// Where the registry was downloaded: `data\oui` next to the program or up to
/// five folders above it (a development build), or `%ProgramData%\win4tress`.
pub fn find() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(program_data) = std::env::var_os("ProgramData") {
        candidates.push(
            PathBuf::from(program_data)
                .join("win4tress")
                .join(FILE_NAME),
        );
    }
    if let Ok(exe) = std::env::current_exe() {
        for dir in exe.ancestors().skip(1).take(5) {
            candidates.push(dir.join(FILE_NAME));
            candidates.push(dir.join("data").join("oui").join(FILE_NAME));
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "Registry,Assignment,Organization Name,Organization Address\n\
MA-L,00155D,Microsoft Corporation,One Microsoft Way Redmond WA US 98052\n\
MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Ning Qiao Road, Shanghai CN\"\n\
MA-M,70B3D5123,Someone,Somewhere\n";

    #[test]
    fn registry_lines_and_lookups() {
        let v = Vendors::parse(CSV);
        assert_eq!(v.len(), 2);
        assert_eq!(
            v.lookup("00-15-5d-01-02-03").as_deref(),
            Some("Microsoft Corporation")
        );
        assert_eq!(
            v.lookup("28:6F:B9:00:00:01").as_deref(),
            Some("Nokia Shanghai Bell Co., Ltd.")
        );
        assert_eq!(v.lookup("aa-bb-cc-00-00-01"), None);
    }

    #[test]
    fn random_addresses() {
        assert!(randomized("da-a1-19-00-00-01"));
        assert!(randomized("02-00-00-00-00-01"));
        assert!(!randomized("00-15-5d-00-00-01"));
    }

    #[test]
    fn broadcast_and_multicast_are_not_devices() {
        assert!(unicast("00-15-5d-00-00-01"));
        assert!(!unicast("ff-ff-ff-ff-ff-ff"));
        assert!(!unicast("01-00-5e-00-00-fb"));
    }
}
