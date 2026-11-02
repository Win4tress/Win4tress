//! What's known about an app's executable, for trust (SPEC §12, tier 1): its
//! signature and signer, its hash, where it lives, and whether it was downloaded.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signature {
    /// A valid Authenticode signature, in the file or in a Windows catalog.
    Signed,
    Unsigned,
    /// Signed, but it doesn't verify: changed after signing, revoked, or an
    /// untrusted root.
    Invalid,
}

impl Signature {
    pub fn as_str(self) -> &'static str {
        match self {
            Signature::Signed => "signed",
            Signature::Unsigned => "unsigned",
            Signature::Invalid => "invalid",
        }
    }

    pub fn parse(s: &str) -> Option<Signature> {
        match s {
            "signed" => Some(Signature::Signed),
            "unsigned" => Some(Signature::Unsigned),
            "invalid" => Some(Signature::Invalid),
            _ => None,
        }
    }
}

/// The file's Mark of the Web: it was downloaded or copied from elsewhere.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadOrigin {
    /// URL zone: 3 Internet, 4 Restricted; lower is local, intranet or trusted.
    pub zone: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer_url: Option<String>,
}

impl DownloadOrigin {
    pub fn from_internet(&self) -> bool {
        self.zone >= 3
    }
}

/// Where an executable lives, by who can write there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    /// Under the Windows folder.
    Windows,
    /// Program Files (and Store apps): only administrators can write there.
    ProgramFiles,
    /// A user's folders (Downloads, AppData, Desktop, Temp): anything the user
    /// runs can write there, malware included.
    UserWritable,
    Other,
}

impl PathClass {
    /// `windows_dir` and `program_dirs` are lower-case with no trailing slash,
    /// e.g. `c:\windows` and `c:\program files`.
    pub fn of(path: &str, windows_dir: &str, program_dirs: &[String]) -> PathClass {
        let p = path.to_lowercase();
        let under = |root: &str| !root.is_empty() && p.starts_with(&format!("{root}\\"));
        if p.contains("\\windowsapps\\") || program_dirs.iter().any(|d| under(d)) {
            PathClass::ProgramFiles
        } else if under(windows_dir) {
            // Writable corners of the Windows folder count as user-writable.
            if p.contains("\\temp\\") || p.contains("\\tasks\\") {
                PathClass::UserWritable
            } else {
                PathClass::Windows
            }
        } else if p.contains("\\users\\") || p.contains("\\temp\\") {
            PathClass::UserWritable
        } else {
            PathClass::Other
        }
    }
}

/// An app's executable as last checked. `None` fields haven't been read (yet).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trust {
    pub signature: Option<Signature>,
    /// The signing certificate's subject (simple display name).
    pub signer: Option<String>,
    /// SHA-256 of the file, lower-case hex.
    pub sha256: Option<String>,
    pub origin: Option<DownloadOrigin>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_classes() {
        let windows = r"c:\windows";
        let programs = [
            r"c:\program files".to_string(),
            r"c:\program files (x86)".into(),
        ];
        let class = |p: &str| PathClass::of(p, windows, &programs);
        assert_eq!(
            class(r"C:\Windows\System32\svchost.exe"),
            PathClass::Windows
        );
        assert_eq!(class(r"C:\Windows\Temp\x.exe"), PathClass::UserWritable);
        assert_eq!(
            class(r"C:\Program Files\App\app.exe"),
            PathClass::ProgramFiles
        );
        assert_eq!(
            class(r"C:\Program Files (x86)\App\app.exe"),
            PathClass::ProgramFiles
        );
        assert_eq!(
            class(r"C:\Program Files\WindowsApps\Calc_1.0\calc.exe"),
            PathClass::ProgramFiles
        );
        assert_eq!(
            class(r"C:\Users\Sam\AppData\Local\Temp\setup.exe"),
            PathClass::UserWritable
        );
        assert_eq!(
            class(r"C:\Users\Sam\Downloads\tool.exe"),
            PathClass::UserWritable
        );
        assert_eq!(class(r"D:\Games\game.exe"), PathClass::Other);
        // Not fooled by a prefix that isn't a folder boundary.
        assert_eq!(class(r"C:\WindowsTools\x.exe"), PathClass::Other);
        assert_eq!(class("System"), PathClass::Other);
    }

    #[test]
    fn signature_names_round_trip() {
        for s in [Signature::Signed, Signature::Unsigned, Signature::Invalid] {
            assert_eq!(Signature::parse(s.as_str()), Some(s));
        }
    }
}
