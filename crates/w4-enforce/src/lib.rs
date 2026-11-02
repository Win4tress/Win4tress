//! Enforcement (SPEC §7, §4.4): win4tress's rules are the desired state; a
//! backend projects them into Windows Firewall and keeps them there.
//!
//! - [`model`]: the Windows Firewall rules a stored rule becomes.
//! - [`plan()`]: the changes that make our rule group match (pure).
//! - [`com`]: the Windows Firewall COM backend (spike 0.2).
//! - [`events`]: Windows Firewall's event log, for seeing outside changes at once.
//! - [`verdict`]: whether an app is allowed or blocked, and by what.

pub mod address;
pub mod com;
pub mod environment;
pub mod events;
pub mod model;
pub mod plan;
pub mod verdict;
pub mod wfp;

use w4_core::firewall::FirewallState;

pub use address::AddressSet;
pub use com::{ComFirewall, expand_env, package_sid};
pub use model::{ActualRule, AppTarget, RuleKey, WindowsRule, package_family, project};
pub use plan::{Change, is_rename_only, plan};
pub use verdict::{OtherRule, OtherRules, default_blocks, verdict};

/// The rule group of the installed service.
pub const GROUP: &str = "win4tress";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{what}: {source}")]
    Windows {
        what: &'static str,
        source: windows::core::Error,
    },
    #[error("the firewall thread has stopped")]
    Stopped,
    #[error("{0}")]
    Invalid(String),
}

impl Error {
    pub fn windows(what: &'static str, source: windows::core::Error) -> Error {
        Error::Windows { what, source }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Where rules are enforced (SPEC §7.12). Every method touches only rules in
/// [`EnforcementBackend::group`].
pub trait EnforcementBackend: Send + Sync {
    fn group(&self) -> &str;
    /// Our group's rules as they are now.
    fn list(&self) -> Result<Vec<ActualRule>>;
    fn apply(&self, change: &Change) -> Result<()>;
    /// Turns the whole group on or off in one step (mode "Off").
    fn set_group_enabled(&self, enabled: bool) -> Result<()>;
    fn state(&self) -> Result<FirewallState>;
    /// Every rule outside our group, read only: what Windows Firewall itself
    /// allows or blocks for each app ([`verdict`]).
    fn others(&self) -> Result<Vec<ActualRule>>;
    /// Turns Windows Firewall on for a profile ("domain", "private", "public").
    /// There's no way to turn it off: win4tress never does.
    fn turn_on(&self, profile: &str) -> Result<()>;
    /// Puts a profile's default actions back (saved before win4tress changed them).
    fn set_defaults(&self, profile: &str, inbound_block: bool, outbound_block: bool) -> Result<()>;
}

/// Removes every rule in the backend's group (uninstall, reset). Returns how many.
pub fn remove_all(backend: &dyn EnforcementBackend) -> Result<usize> {
    let mut removed = 0;
    // Same-named copies are removed one per call, so repeat (bounded).
    for _ in 0..5 {
        let rules = backend.list()?;
        if rules.is_empty() {
            break;
        }
        for r in rules {
            backend.apply(&Change::Delete { name: r.name })?;
            removed += 1;
        }
    }
    Ok(removed)
}
