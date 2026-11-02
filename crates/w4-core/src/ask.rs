//! Ask to Connect (SPEC §7.4): what's allowed out without asking.

use crate::trust::{PathClass, Signature, Trust};

const BASELINE: &str = include_str!("../../../data/baseline-services.txt");
const ABUSED: &str = include_str!("../../../data/abused-system-tools.txt");

/// Signers of Windows' own files (the signing certificate's display name).
const MICROSOFT_SIGNERS: &[&str] = &[
    "Microsoft Windows",
    "Microsoft Windows Publisher",
    "Microsoft Corporation",
];

/// A Windows service or program allowed out while Ask to Connect is on
/// (`data/baseline-services.txt`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaselineEntry {
    pub label: String,
    pub target: BaselineTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaselineTarget {
    /// Matched by the service's SID, whatever program hosts it.
    Service(String),
    /// A program path; may contain environment variables.
    Program(String),
}

pub fn baseline() -> Vec<BaselineEntry> {
    parse_baseline(BASELINE)
}

/// File names, in lower case, of built-in tools that always ask
/// (`data/abused-system-tools.txt`).
pub fn abused_tools() -> Vec<String> {
    lines(ABUSED).map(str::to_ascii_lowercase).collect()
}

fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

fn parse_baseline(text: &str) -> Vec<BaselineEntry> {
    lines(text)
        .filter_map(|line| {
            let (label, target) = line.split_once('|')?;
            let target = target.trim();
            let target = if let Some(name) = target.strip_prefix("service ") {
                BaselineTarget::Service(name.trim().to_string())
            } else {
                BaselineTarget::Program(target.strip_prefix("program ")?.trim().to_string())
            };
            Some(BaselineEntry {
                label: label.trim().to_string(),
                target,
            })
        })
        .collect()
}

/// Whether an app blocked in Ask to Connect is allowed without asking, on its
/// first block: the kernel, or a Microsoft-signed program in the Windows
/// folder that isn't one of the tools malware abuses (`abused`, lower case).
pub fn allowed_without_asking(
    path: &str,
    path_class: Option<PathClass>,
    trust: &Trust,
    abused: &[String],
) -> bool {
    if path == "System" {
        return true;
    }
    let file = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    path_class == Some(PathClass::Windows)
        && trust.signature == Some(Signature::Signed)
        && trust
            .signer
            .as_deref()
            .is_some_and(|s| MICROSOFT_SIGNERS.contains(&s))
        && !abused.contains(&file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_lists_parse() {
        let baseline = baseline();
        assert!(baseline.len() >= 20);
        assert!(
            baseline.iter().any(|e| e.label == "DNS Client"
                && e.target == BaselineTarget::Service("Dnscache".into()))
        );
        assert!(baseline.iter().any(|e| matches!(
            &e.target,
            BaselineTarget::Program(p) if p.ends_with(r"\MpCmdRun.exe")
        )));
        let abused = abused_tools();
        assert!(abused.contains(&"powershell.exe".to_string()));
        assert!(abused.iter().all(|t| t == &t.to_ascii_lowercase()));
    }

    #[test]
    fn baseline_lines_without_a_known_target_are_skipped() {
        let parsed = parse_baseline(
            "# note\nA | service X\nB | registry Y\nno bar\nC | program %SystemRoot%\\c.exe\n",
        );
        assert_eq!(
            parsed,
            [
                BaselineEntry {
                    label: "A".into(),
                    target: BaselineTarget::Service("X".into())
                },
                BaselineEntry {
                    label: "C".into(),
                    target: BaselineTarget::Program(r"%SystemRoot%\c.exe".into())
                },
            ]
        );
    }

    #[test]
    fn who_is_allowed_without_asking() {
        let abused = abused_tools();
        let signed = |signer: &str| Trust {
            signature: Some(Signature::Signed),
            signer: Some(signer.into()),
            ..Default::default()
        };
        let ms = signed("Microsoft Windows");
        let system32 = |file: &str| format!(r"C:\Windows\System32\{file}");
        let allowed =
            |path: &str, class, trust: &Trust| allowed_without_asking(path, class, trust, &abused);
        assert!(allowed("System", None, &Trust::default()));
        assert!(allowed(
            &system32("svchost.exe"),
            Some(PathClass::Windows),
            &ms
        ));
        // The tools malware abuses ask, in any case.
        assert!(!allowed(
            &system32("PowerShell.EXE"),
            Some(PathClass::Windows),
            &ms
        ));
        // Not Microsoft's, not signed, not in the Windows folder, not read yet.
        assert!(!allowed(
            &system32("x.exe"),
            Some(PathClass::Windows),
            &signed("Contoso")
        ));
        assert!(!allowed(
            &system32("x.exe"),
            Some(PathClass::Windows),
            &Trust {
                signature: Some(Signature::Unsigned),
                ..Default::default()
            }
        ));
        assert!(!allowed(r"C:\Tools\x.exe", Some(PathClass::Other), &ms));
        assert!(!allowed(
            &system32("x.exe"),
            Some(PathClass::Windows),
            &Trust::default()
        ));
    }
}
