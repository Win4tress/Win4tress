//! Spike 0.2 (docs/PLAN.md): can win4tress manage Windows Firewall rules from
//! Rust through the COM API? Creates, reads back, changes and deletes rules with
//! program, service, package and address conditions, checks that blocking takes
//! effect, and times each operation and a batch.
//!
//! Run elevated. Every rule it makes is in the group "win4tress spike" and is
//! removed at the end (and at the start, in case an earlier run crashed). Rules
//! that block anything apply only to a private copy of curl.exe.

mod blocks;
mod env;
mod etw;
mod fw;
mod wfp;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;

use fw::{Firewall, RuleSpec, view};

const GROUP: &str = "win4tress spike";
const PREFIX: &str = "win4tress-spike";
/// Reached directly by IP, so no DNS is involved.
const HOST_A: &str = "1.1.1.1";
const HOST_B: &str = "8.8.8.8";
/// A Store app present on Windows 11, for the package condition.
const PACKAGE_FAMILY: &str = "Microsoft.WindowsCalculator_8wekyb3d8bbwe";

#[derive(Parser)]
#[command(about = "Spike 0.2: Windows Firewall rules from Rust (COM)")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run every check (elevated); leaves no rules behind
    Run {
        /// Folder for results.json and results.md
        #[arg(long)]
        out: PathBuf,
        /// Rules in the batch timing test
        #[arg(long, default_value_t = 200)]
        batch: usize,
    },
    /// Spike 0.4: block notifications mapped to rules, and their latency (elevated)
    Blocks {
        /// Folder for results.json and results.md
        #[arg(long)]
        out: PathBuf,
        /// Seconds to record other drops (inbound default block etc.) afterwards
        #[arg(long, default_value_t = 30)]
        idle_secs: u64,
    },
    /// Block the test app and make connection attempts, writing their times to
    /// attempts.json (for correlating with a trace taken around it; elevated)
    Attempts {
        #[arg(long)]
        out: PathBuf,
    },
    /// Spike 0.5: the firewall environment (Security Center, policy); read-only
    Env {
        #[arg(long)]
        out: PathBuf,
    },
    /// Spike 0.4: switch outbound default to block for a few seconds and check
    /// the drop names the default filter (elevated; restores the setting)
    DefaultBlock {
        #[arg(long)]
        out: PathBuf,
    },
    /// Spike 0.4: WFP drop → ETW callback delay under several session settings
    /// (elevated; blocks only the test app)
    EtwLatency {
        #[arg(long)]
        out: PathBuf,
    },
    /// Remove rules an interrupted run left behind (elevated)
    Cleanup,
}

#[derive(Serialize)]
struct Check {
    name: String,
    /// pass, fail, info or skip
    result: &'static str,
    detail: String,
    ms: Option<f64>,
}

#[derive(Default, Serialize)]
struct Report {
    policy: Option<fw::PolicyStatus>,
    checks: Vec<Check>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    drops: Vec<wfp::DropEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    filters: Vec<wfp::FilterInfo>,
}

impl Report {
    fn push(
        &mut self,
        name: &str,
        result: &'static str,
        detail: impl Into<String>,
        ms: Option<f64>,
    ) {
        let detail = detail.into();
        println!(
            "[{result:>4}] {name}{}{}",
            ms.map(|m| format!(" ({m:.1} ms)")).unwrap_or_default(),
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        );
        self.checks.push(Check {
            name: name.into(),
            result,
            detail,
            ms,
        });
    }
    fn check(&mut self, name: &str, ok: bool, detail: impl Into<String>, ms: Option<f64>) {
        self.push(name, if ok { "pass" } else { "fail" }, detail, ms);
    }
    fn info(&mut self, name: &str, detail: impl Into<String>, ms: Option<f64>) {
        self.push(name, "info", detail, ms);
    }
}

/// Removes the spike's rules however the run ends.
struct Cleanup<'a>(&'a Firewall);

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        match self.0.clear_group(GROUP) {
            Ok(0) => {}
            Ok(n) => println!("cleanup: removed {n} leftover rules"),
            Err(e) => eprintln!("cleanup failed: {e:#}"),
        }
    }
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::Run { out, batch } => run(&out, batch),
        Cmd::Blocks { out, idle_secs } => blocks::run(&out, idle_secs),
        Cmd::Attempts { out } => blocks::attempts_only(&out),
        Cmd::Env { out } => env::run(&out),
        Cmd::DefaultBlock { out } => blocks::default_block(&out),
        Cmd::EtwLatency { out } => etw::latency(&out),
        Cmd::Cleanup => {
            let fw = Firewall::open()?;
            println!("removed {} rules", fw.clear_group(GROUP)?);
            Ok(())
        }
    }
}

/// A private copy of curl, so block rules can't affect anything else.
fn test_exe() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("w4-fw-spike");
    std::fs::create_dir_all(&dir)?;
    let exe = dir.join("w4fwtest.exe");
    let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    std::fs::copy(Path::new(&system).join(r"System32\curl.exe"), &exe)
        .context("copying curl.exe")?;
    Ok(exe)
}

/// Whether the test exe can open an HTTPS connection to `ip`, and how long it took.
fn reach(exe: &Path, ip: &str) -> (bool, f64) {
    let t = Instant::now();
    let ok = Command::new(exe)
        .args([
            "-s",
            "-k",
            "-o",
            "NUL",
            "-m",
            "5",
            &format!("https://{ip}/"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    (ok, ms(t))
}

fn reach_both(exe: &Path) -> (bool, bool) {
    (reach(exe, HOST_A).0, reach(exe, HOST_B).0)
}

fn spec(name: &str) -> RuleSpec {
    RuleSpec {
        name: format!("{PREFIX}/{name}"),
        group: GROUP.into(),
        enabled: true,
        ..Default::default()
    }
}

/// Everything except `ip` (an IPv4 address), plus all of IPv6: how an
/// "allow only these hosts" rule becomes a block rule.
fn complement_v4(ip: &str) -> Result<String> {
    let n = u32::from(ip.parse::<std::net::Ipv4Addr>()?);
    let fmt = |v: u32| std::net::Ipv4Addr::from(v).to_string();
    let mut parts = Vec::new();
    if n > 0 {
        parts.push(format!("0.0.0.0-{}", fmt(n - 1)));
    }
    if n < u32::MAX {
        parts.push(format!("{}-255.255.255.255", fmt(n + 1)));
    }
    parts.push("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into());
    Ok(parts.join(","))
}

fn run(out: &Path, batch: usize) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let t = Instant::now();
    let fw = Firewall::open()?;
    let open_ms = ms(t);
    let _cleanup = Cleanup(&fw);
    let leftovers = fw.clear_group(GROUP)?;

    let mut r = Report::default();
    r.info(
        "open INetFwPolicy2",
        format!("{leftovers} leftover rules removed"),
        Some(open_ms),
    );
    let status = fw.status()?;
    r.info(
        "policy",
        format!(
            "{} rules; modify state {}; {}",
            status.rule_count,
            status.modify_state,
            status
                .profiles
                .iter()
                .map(|p| format!(
                    "{}{}: firewall {}, inbound default {}, outbound default {}",
                    p.name,
                    if p.active { " (active)" } else { "" },
                    if p.firewall_on { "on" } else { "off" },
                    if p.default_inbound_block {
                        "block"
                    } else {
                        "allow"
                    },
                    if p.default_outbound_block {
                        "block"
                    } else {
                        "allow"
                    },
                ))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        None,
    );
    r.policy = Some(status);

    let exe = test_exe()?;
    let exe_s = exe.display().to_string();
    let (base_a, base_b) = reach_both(&exe);
    let enforce = fw.enforcing()? && base_a && base_b;
    let why_not = if !fw.enforcing()? {
        "firewall is off for an active profile"
    } else {
        "the test hosts aren't reachable without rules"
    };
    r.info(
        "baseline",
        format!("{HOST_A} reachable: {base_a}, {HOST_B} reachable: {base_b}"),
        None,
    );
    let enforced = |r: &mut Report, name: &str, want: (bool, bool)| {
        if !enforce {
            r.push(name, "skip", why_not, None);
            return;
        }
        let t = Instant::now();
        let got = reach_both(&exe);
        r.check(
            name,
            got == want,
            format!(
                "{HOST_A} reachable {} (want {}), {HOST_B} reachable {} (want {})",
                got.0, want.0, got.1, want.1
            ),
            Some(ms(t)),
        );
    };

    // 1. Program rule: create, read back, enforce.
    let prog = RuleSpec {
        program: Some(exe_s.clone()),
        ..spec("program")
    };
    let t = Instant::now();
    fw.add(&prog)?;
    r.info("add program block rule", "", Some(ms(t)));
    let v = view(&fw.get(&prog.name)?)?;
    r.check(
        "read back program rule",
        v.program.eq_ignore_ascii_case(&exe_s)
            && v.group == GROUP
            && !v.inbound
            && !v.allow
            && v.enabled,
        format!("{v:?}"),
        None,
    );
    enforced(&mut r, "blocks immediately after Add", (false, false));

    // 2. Change the remote addresses of an existing rule.
    let t = Instant::now();
    fw.set_remote_addresses(&prog.name, HOST_B)?;
    r.info("update remote addresses", "", Some(ms(t)));
    let v = view(&fw.get(&prog.name)?)?;
    r.info(
        "remote addresses read back as",
        v.remote_addresses.clone(),
        None,
    );
    enforced(&mut r, "blocks only the new address", (true, false));

    // 3. Disable and re-enable one rule, then the whole group.
    let t = Instant::now();
    fw.set_enabled(&prog.name, false)?;
    r.info("disable rule", "", Some(ms(t)));
    enforced(&mut r, "disabled rule doesn't block", (true, true));
    fw.set_enabled(&prog.name, true)?;
    enforced(&mut r, "re-enabled rule blocks again", (true, false));
    let t = Instant::now();
    fw.enable_group(GROUP, false)?;
    let group_off_ms = ms(t);
    r.check(
        "disable rule group",
        !fw.group_enabled(GROUP)?,
        "",
        Some(group_off_ms),
    );
    enforced(&mut r, "disabled group doesn't block", (true, true));
    fw.enable_group(GROUP, true)?;
    r.check("enable rule group", fw.group_enabled(GROUP)?, "", None);
    enforced(&mut r, "re-enabled group blocks again", (true, false));

    // 4. Delete.
    let t = Instant::now();
    fw.remove(&prog.name)?;
    r.info("remove rule", "", Some(ms(t)));
    r.check("rule is gone", fw.get(&prog.name).is_err(), "", None);
    enforced(&mut r, "nothing blocked after removal", (true, true));

    // 5. "Allow only HOST_A" as a block rule on the complement.
    let only = RuleSpec {
        program: Some(exe_s.clone()),
        remote_addresses: Some(complement_v4(HOST_A)?),
        ..spec("allow-only")
    };
    let t = Instant::now();
    fw.add(&only)?;
    r.info(
        "add complement (allow-only) rule",
        only.remote_addresses.clone().unwrap_or_default(),
        Some(ms(t)),
    );
    enforced(
        &mut r,
        "complement rule allows only its host",
        (true, false),
    );
    fw.remove(&only.name)?;

    // 6. Block beats allow for the same program.
    let allow = RuleSpec {
        program: Some(exe_s.clone()),
        allow: true,
        ..spec("allow-all")
    };
    let block = RuleSpec {
        program: Some(exe_s.clone()),
        remote_addresses: Some(HOST_B.into()),
        ..spec("block-one")
    };
    fw.add(&allow)?;
    fw.add(&block)?;
    enforced(&mut r, "block rule wins over allow rule", (true, false));
    fw.remove(&allow.name)?;
    fw.remove(&block.name)?;

    // 7. Conditions that aren't enforced here (rules created disabled): read back only.
    let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let svchost = format!(r"{system}\System32\svchost.exe");
    let service = RuleSpec {
        program: Some(svchost.clone()),
        service: Some("Dnscache".into()),
        enabled: false,
        ..spec("service")
    };
    match fw.add(&service).and_then(|_| view(&fw.get(&service.name)?)) {
        Ok(v) => r.check(
            "service condition (svchost + Dnscache)",
            v.service.eq_ignore_ascii_case("Dnscache") && v.program.eq_ignore_ascii_case(&svchost),
            format!("{v:?}"),
            None,
        ),
        Err(e) => r.check(
            "service condition (svchost + Dnscache)",
            false,
            format!("{e:#}"),
            None,
        ),
    }
    let service_only = RuleSpec {
        service: Some("Dnscache".into()),
        enabled: false,
        ..spec("service-only")
    };
    match fw
        .add(&service_only)
        .and_then(|_| view(&fw.get(&service_only.name)?))
    {
        Ok(v) => r.info(
            "service condition without a program",
            format!("{v:?}"),
            None,
        ),
        Err(e) => r.info(
            "service condition without a program",
            format!("rejected: {e:#}"),
            None,
        ),
    }
    match fw::package_sid(PACKAGE_FAMILY) {
        Ok(sid) => {
            let pkg = RuleSpec {
                package_sid: Some(sid.clone()),
                enabled: false,
                ..spec("package")
            };
            match fw.add(&pkg).and_then(|_| view(&fw.get(&pkg.name)?)) {
                Ok(v) => r.check(
                    "package condition (Calculator)",
                    v.package_sid.eq_ignore_ascii_case(&sid),
                    format!("{v:?}"),
                    None,
                ),
                Err(e) => r.check(
                    "package condition (Calculator)",
                    false,
                    format!("{e:#}"),
                    None,
                ),
            }
        }
        Err(e) => r.check("package SID", false, format!("{e:#}"), None),
    }
    let inbound = RuleSpec {
        program: Some(exe_s.clone()),
        inbound: true,
        enabled: false,
        ..spec("inbound")
    };
    match fw.add(&inbound).and_then(|_| view(&fw.get(&inbound.name)?)) {
        Ok(v) => r.check("inbound rule", v.inbound, format!("{v:?}"), None),
        Err(e) => r.check("inbound rule", false, format!("{e:#}"), None),
    }

    // 8. Long address lists (per-host rules can need hundreds of addresses).
    for n in [1_000usize, 10_000] {
        let list: Vec<String> = (0..n)
            .map(|i| format!("10.{}.{}.{}", 100 + i / 65_536, (i / 256) % 256, i % 256))
            .collect();
        let rule = RuleSpec {
            program: Some(exe_s.clone()),
            remote_addresses: Some(list.join(",")),
            enabled: false,
            ..spec(&format!("list-{n}"))
        };
        let t = Instant::now();
        match fw.add(&rule) {
            Ok(()) => {
                let add_ms = ms(t);
                let back = view(&fw.get(&rule.name)?)?.remote_addresses;
                let count = back.split(',').filter(|s| !s.is_empty()).count();
                r.check(
                    &format!("{n} remote addresses"),
                    count == n,
                    format!("{count} read back, {} characters", back.len()),
                    Some(add_ms),
                );
            }
            Err(e) => r.check(
                &format!("{n} remote addresses"),
                false,
                format!("{e:#}"),
                Some(ms(t)),
            ),
        }
    }

    // 9. Two rules with one name: what does Remove(name) do?
    let dup = RuleSpec {
        program: Some(exe_s.clone()),
        enabled: false,
        ..spec("duplicate")
    };
    fw.add(&dup)?;
    fw.add(&dup)?;
    fw.remove(&dup.name)?;
    let left = fw
        .in_group(GROUP)?
        .iter()
        .filter(|v| v.name == dup.name)
        .count();
    r.info(
        "Remove(name) with two same-named rules",
        format!("{left} left"),
        None,
    );

    // 10. Batch: create, enumerate, look up, delete.
    let before = fw.count()?;
    let names: Vec<String> = (0..batch)
        .map(|i| format!("{PREFIX}/batch/{i:04}"))
        .collect();
    let t = Instant::now();
    for name in &names {
        fw.add(&RuleSpec {
            name: name.clone(),
            group: GROUP.into(),
            program: Some(exe_s.clone()),
            enabled: false,
            ..Default::default()
        })?;
    }
    let add_ms = ms(t);
    r.info(
        &format!("add {batch} rules"),
        format!("{:.2} ms per rule", add_ms / batch as f64),
        Some(add_ms),
    );
    let t = Instant::now();
    let total = fw.all()?.len();
    let enum_ms = ms(t);
    r.info(
        "enumerate all rules",
        format!("{total} rules ({before} before the batch)"),
        Some(enum_ms),
    );
    let t = Instant::now();
    let in_group = fw.in_group(GROUP)?.len();
    r.info(
        "enumerate and read every rule, filter by group",
        format!("{in_group} in the group"),
        Some(ms(t)),
    );
    let t = Instant::now();
    fw.get(&names[batch / 2])?;
    r.info("look up one rule by name", "", Some(ms(t)));
    let t = Instant::now();
    for name in &names {
        fw.remove(name)?;
    }
    let del_ms = ms(t);
    r.info(
        &format!("remove {batch} rules"),
        format!("{:.2} ms per rule", del_ms / batch as f64),
        Some(del_ms),
    );

    // 11. Nothing left behind.
    fw.clear_group(GROUP)?;
    let left = fw.in_group(GROUP)?.len();
    r.check(
        "no spike rules left",
        left == 0,
        format!("{left} left"),
        None,
    );
    r.check(
        "rule count back to start",
        fw.count()? == r.policy.as_ref().map_or(0, |p| p.rule_count),
        "",
        None,
    );

    let _ = std::fs::remove_file(&exe);
    write_report(out, &r)?;
    let failed = r.checks.iter().filter(|c| c.result == "fail").count();
    println!(
        "\n{} checks, {failed} failed. Results in {}",
        r.checks.len(),
        out.display()
    );
    Ok(())
}

fn write_report(out: &Path, r: &Report) -> Result<()> {
    std::fs::write(out.join("results.json"), serde_json::to_string_pretty(r)?)?;
    let mut md = String::from("| Check | Result | Time | Detail |\n|---|---|---|---|\n");
    for c in &r.checks {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            c.name,
            c.result,
            c.ms.map(|m| format!("{m:.1} ms")).unwrap_or_default(),
            c.detail.replace('|', "\\|"),
        ));
    }
    std::fs::write(out.join("results.md"), md)?;
    Ok(())
}
