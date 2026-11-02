//! DNS filtering in the service (SPEC §13, PLAN Phase 7): downloads the chosen
//! blocklists (skipping unchanged ones by ETag, never on metered
//! connections), compiles them for the resolver, writes its config, keeps the
//! resolver (`win4tress-dns`) running, and routes Windows' lookups to it with
//! an NRPT rule only while it answers. The watchdog takes the rule away after
//! four missed health checks 500 ms apart (spike 0.7: Windows' DNS is back in
//! under 2 s), and puts it back once the resolver answers again.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use w4_core::time::now_unix_ms;
use w4_dns::catalogue;
use w4_dns::compile::{compile, new_key, write_atomic};
use w4_dns::config::{self as dnsconf, CONFIG_FILE, Config, HEALTH_NAME};
use w4_dns::lists::{Format, parse};
use w4_dns::status::{LogParams, LogResult, ResolverStatus};
use w4_dns::wire;
use w4_ipc::api::{
    AlertBody, CustomList, DnsFilterLogEntry, DnsFilterState, DnsFilterStatus, DnsListState,
    DnsObserve, DnsSettings, DnsUpstream,
};
use w4_monitor::Monitor;

use crate::usage::Usage;

const TICK: Duration = Duration::from_millis(500);
/// Missed health checks in a row before Windows' DNS is put back (2 s).
const MISSES_TO_RESTORE: u32 = 4;
/// Answered checks in a row before lookups are routed to the resolver.
const ANSWERS_TO_ROUTE: u32 = 2;
const HEALTH_TIMEOUT: Duration = Duration::from_millis(300);
const LIST_EVERY_MS: i64 = 24 * 3600 * 1000;
const LIST_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;
const RESTART_AFTER: Duration = Duration::from_secs(2);
/// The resolver's status unreadable this long, while it's answering: a problem
/// to show (a starting resolver's pipe isn't up at once).
const UNREADABLE_AFTER: Duration = Duration::from_secs(10);
/// How long a resolver's "blocked" stays matched to the DNS log.
const BLOCKED_NAMES_KEEP_MS: i64 = 15 * 60 * 1000;
const MAX_BLOCKED_NAMES: usize = 5_000;
/// CREATE_NO_WINDOW: the resolver gets no console of its own.
const NO_WINDOW: u32 = 0x0800_0000;
/// The resolver's folder: LocalService (the resolver, installed) reads its
/// config and blocklist; only SYSTEM and Administrators change them.
const DNS_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;LS)";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A list's download state, kept beside the downloaded files.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ListMeta {
    etag: Option<String>,
    updated_ms: Option<i64>,
    checked_ms: Option<i64>,
    entries: Option<u32>,
    error: Option<String>,
}

/// One chosen list: a catalogue entry or the user's own.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Chosen {
    id: String,
    name: String,
    url: String,
    format: Format,
}

fn chosen(s: &DnsSettings) -> Vec<Chosen> {
    let mut out: Vec<Chosen> = s
        .lists
        .iter()
        .filter_map(|id| catalogue::find(id))
        .map(|e| Chosen {
            id: e.id.to_string(),
            name: e.name.to_string(),
            url: e.url.to_string(),
            format: e.format,
        })
        .collect();
    out.extend(s.custom_lists.iter().map(|c| Chosen {
        id: custom_id(c),
        name: c.name.clone(),
        url: c.url.clone(),
        format: if c.regex {
            Format::Regex
        } else {
            Format::Domains
        },
    }));
    out
}

/// A list of the user's own's id, from its address: removing one list never
/// hands another its download. FNV-1a, which (unlike `DefaultHasher`) stays
/// the same across Rust versions.
fn custom_id(c: &CustomList) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in c.url.bytes().chain([u8::from(c.regex)]) {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("custom-{h:016x}")
}

/// The DNS servers the resolver asks: every connected adapter's, those with
/// a gateway first, without loopback or Windows' `fec0::ffff` placeholders.
pub fn system_servers() -> Vec<IpAddr> {
    let mut adapters = w4_sys::netinfo::adapters();
    adapters.retain(|a| a.up);
    adapters.sort_by_key(|a| a.gateways.is_empty());
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in adapters.iter().flat_map(|a| a.dns.iter().copied()) {
        let skip = ip.is_loopback()
            || ip.is_unspecified()
            || matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfec0);
        if !skip && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

fn local_suffixes() -> Vec<String> {
    let mut out: Vec<String> = w4_sys::netinfo::adapters()
        .into_iter()
        .filter(|a| a.up)
        .filter_map(|a| a.dns_suffix)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A sign-in page: on a network with a gateway, but no internet yet.
fn captive() -> bool {
    w4_sys::netinfo::internet() == Some(false)
        && w4_sys::netinfo::adapters()
            .iter()
            .any(|a| a.up && !a.gateways.is_empty())
}

/// The resolver's config from the settings and what's compiled.
fn build_config(
    s: &DnsSettings,
    compiled: Option<&Compiled>,
    servers: Vec<IpAddr>,
    passthrough: bool,
) -> Config {
    let mut regex = s.regex.clone();
    if let Some(c) = compiled {
        regex.extend(c.regex.iter().cloned());
    }
    Config {
        filtering: true,
        observe: match s.observe {
            DnsObserve::Auto => dnsconf::Observe::Auto,
            DnsObserve::On => dnsconf::Observe::On,
            DnsObserve::Off => dnsconf::Observe::Off,
        },
        block_answer: if s.nxdomain {
            dnsconf::BlockAnswer::Nxdomain
        } else {
            dnsconf::BlockAnswer::NullIp
        },
        upstream: match &s.upstream {
            DnsUpstream::System => dnsconf::Upstream::System,
            DnsUpstream::Doh { url } => dnsconf::Upstream::Doh { url: url.clone() },
        },
        system_servers: servers,
        local_suffixes: local_suffixes(),
        passthrough,
        paused_until_ms: s.paused_until_ms,
        allow: s.allow.clone(),
        deny: s.deny.clone(),
        regex,
        local_records: s
            .local_records
            .iter()
            .map(|r| dnsconf::LocalRecord {
                name: r.name.clone(),
                addrs: r.addrs.clone(),
            })
            .collect(),
        blocklist: compiled.map(|c| c.file.clone()),
        lists: compiled.map(|c| c.names.clone()).unwrap_or_default(),
    }
}

/// What's compiled now, and from which downloads.
#[derive(Clone, Debug)]
struct Compiled {
    /// The chosen lists and each download's time: compiled again when it changes.
    from: Vec<(String, Option<i64>)>,
    file: String,
    domains: usize,
    regex: Vec<String>,
    names: Vec<dnsconf::ListName>,
}

/// The resolver process: as LocalService when the service runs as SYSTEM
/// (installed), otherwise with the service's own account (console runs).
enum Resolver {
    Limited(w4_sys::process::Spawned),
    Plain(Child),
}

impl Resolver {
    fn id(&self) -> u32 {
        match self {
            Resolver::Limited(p) => p.id(),
            Resolver::Plain(c) => c.id(),
        }
    }

    fn account(&self) -> &'static str {
        match self {
            Resolver::Limited(_) => "LocalService",
            Resolver::Plain(_) => "the service's account",
        }
    }

    /// How it ended, once it has.
    fn try_wait(&mut self) -> std::io::Result<Option<String>> {
        Ok(match self {
            Resolver::Limited(p) => p.try_wait()?.map(|code| format!("exit code: {code}")),
            Resolver::Plain(c) => c.try_wait()?.map(|status| status.to_string()),
        })
    }

    fn kill(&mut self) {
        match self {
            Resolver::Limited(p) => p.kill(),
            Resolver::Plain(c) => {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

#[derive(Default)]
struct State {
    child: Option<Resolver>,
    restart_after: Option<Instant>,
    routed: bool,
    misses: u32,
    answers: u32,
    restores: u32,
    message: Option<String>,
    failed: bool,
    compiled: Option<Compiled>,
    written: Option<Config>,
    lists: HashMap<String, ListMeta>,
    last_update_ms: Option<i64>,
    resolver: Option<ResolverStatus>,
    /// Since when, and why, the resolver's status can't be read.
    unreadable: Option<(Instant, String)>,
    last_log_id: u64,
    started_ms: Option<i64>,
    /// The settings the last config was made from: a change applies at once.
    seen: Option<DnsSettings>,
}

pub struct DnsFilter {
    usage: Arc<Usage>,
    monitor: Arc<Mutex<Monitor>>,
    dir: PathBuf,
    resolver_exe: PathBuf,
    pipe: String,
    state: Mutex<State>,
    /// Names the resolver blocked lately → (why, when), for the DNS log.
    blocked: Mutex<HashMap<String, (String, i64)>>,
    updating: AtomicBool,
    force_update: AtomicBool,
}

impl DnsFilter {
    pub fn new(
        usage: Arc<Usage>,
        monitor: Arc<Mutex<Monitor>>,
        data_dir: &Path,
        pipe: String,
    ) -> Arc<DnsFilter> {
        let dir = data_dir.join("dns");
        let resolver_exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("win4tress-dns.exe")))
            .unwrap_or_else(|| PathBuf::from("win4tress-dns.exe"));
        let lists = std::fs::read_to_string(dir.join("lists").join("meta.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Arc::new(DnsFilter {
            usage,
            monitor,
            dir,
            resolver_exe,
            pipe,
            state: Mutex::new(State {
                lists,
                ..State::default()
            }),
            blocked: Mutex::new(HashMap::new()),
            updating: AtomicBool::new(false),
            force_update: AtomicBool::new(false),
        })
    }

    fn settings(&self) -> DnsSettings {
        self.usage.settings().dns
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        // A rule left by a crash routes lookups nowhere: away first.
        if w4_sys::nrpt::present() {
            match w4_sys::nrpt::remove() {
                Ok(_) => {
                    tracing::warn!("removed a DNS filtering NRPT rule left from an earlier run")
                }
                Err(e) => tracing::error!("can't remove a leftover NRPT rule: {e}"),
            }
        }
        if let Err(e) = w4_sys::fs::create_private_dir(&self.dir, DNS_DIR_SDDL) {
            tracing::warn!("can't set up {}: {e}", self.dir.display());
        }
        // A resolver left running by a service that crashed holds port 53.
        let ended = w4_sys::process::kill_all(&self.resolver_exe);
        if ended > 0 {
            tracing::warn!(ended, "ended a DNS resolver left from an earlier run");
        }
        let mut tick = tokio::time::interval(TICK);
        let mut n: u64 = 0;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tick.tick() => {}
            }
            n += 1;
            self.step(n).await;
        }
        self.stop("the service stopped");
    }

    /// Off: no rule, no resolver.
    pub fn stop(&self, why: &str) {
        let mut s = lock(&self.state);
        if s.routed || w4_sys::nrpt::present() {
            match w4_sys::nrpt::remove() {
                Ok(_) => tracing::info!("DNS filtering off ({why}): Windows' DNS as before"),
                Err(e) => tracing::error!("removing the NRPT rule: {e}"),
            }
            s.routed = false;
        }
        if let Some(mut child) = s.child.take() {
            child.kill();
        }
        s.misses = 0;
        s.answers = 0;
        s.failed = false;
        s.message = None;
        s.seen = None;
    }

    async fn step(self: &Arc<Self>, n: u64) {
        let settings = self.settings();
        if !settings.enabled {
            let active = {
                let s = lock(&self.state);
                s.routed || s.child.is_some()
            };
            if active {
                self.stop("turned off");
            }
            return;
        }
        // Every 5 s, and at once when the settings change: downloads,
        // compiling, the config (servers change with networks).
        let changed = lock(&self.state).seen.as_ref() != Some(&settings);
        if n % 10 == 1 || changed {
            lock(&self.state).seen = Some(settings.clone());
            self.maybe_update(&settings);
            let this = Arc::clone(self);
            let s2 = settings.clone();
            let _ = tokio::task::spawn_blocking(move || {
                this.maybe_compile(&s2);
                this.write_config(&s2);
                this.remove_old_lists();
            })
            .await;
        }
        self.ensure_resolver();
        let healthy = health_check().await;
        self.on_health(healthy);
        if n.is_multiple_of(4) {
            self.poll_resolver().await;
        }
    }

    fn lists_dir(&self) -> PathBuf {
        self.dir.join("lists")
    }

    fn save_meta(&self, lists: &HashMap<String, ListMeta>) {
        if let Ok(json) = serde_json::to_string_pretty(lists) {
            let _ = std::fs::create_dir_all(self.lists_dir());
            let _ = write_atomic(&self.lists_dir().join("meta.json"), json.as_bytes());
        }
    }

    /// Downloads in the background whatever is due (or everything, when asked).
    fn maybe_update(self: &Arc<Self>, settings: &DnsSettings) {
        if self.updating.load(Ordering::Relaxed) {
            return;
        }
        let force = self.force_update.swap(false, Ordering::Relaxed);
        let now = now_unix_ms();
        let lists = lock(&self.state).lists.clone();
        let due: Vec<Chosen> = chosen(settings)
            .into_iter()
            .filter(|c| {
                let file = self.lists_dir().join(format!("{}.txt", c.id));
                force
                    || !file.exists()
                    || lists
                        .get(&c.id)
                        .and_then(|m| m.checked_ms)
                        .is_none_or(|t| now - t >= LIST_EVERY_MS)
            })
            .collect();
        if due.is_empty() {
            return;
        }
        if self.usage.save_context().metered && !force {
            lock(&self.state).message =
                Some("blocklists wait for a connection that isn't metered".into());
            return;
        }
        self.updating.store(true, Ordering::Relaxed);
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            for c in due {
                this.download(&c);
            }
            lock(&this.state).last_update_ms = Some(now_unix_ms());
            this.updating.store(false, Ordering::Relaxed);
        });
    }

    fn download(&self, c: &Chosen) {
        let _ = std::fs::create_dir_all(self.lists_dir());
        let file = self.lists_dir().join(format!("{}.txt", c.id));
        let mut meta = lock(&self.state)
            .lists
            .get(&c.id)
            .cloned()
            .unwrap_or_default();
        let etag = meta.etag.clone().filter(|_| file.exists());
        let mut headers = vec![("Accept", "text/plain")];
        if let Some(e) = &etag {
            headers.push(("If-None-Match", e.as_str()));
        }
        let now = now_unix_ms();
        meta.checked_ms = Some(now);
        match w4_sys::http::request("GET", &c.url, &headers, None, MAX_LIST_BYTES, LIST_TIMEOUT) {
            Ok(r) if r.status == 304 => {
                meta.error = None;
                tracing::info!(list = %c.id, "blocklist unchanged");
            }
            Ok(r) if r.status == 200 => match write_atomic(&file, &r.body) {
                Ok(()) => {
                    meta.etag = r.etag;
                    meta.updated_ms = Some(now);
                    meta.error = None;
                    tracing::info!(list = %c.id, bytes = r.body.len(), "blocklist downloaded");
                }
                Err(e) => meta.error = Some(format!("saving: {e}")),
            },
            Ok(r) => meta.error = Some(format!("HTTP {}", r.status)),
            Err(e) => meta.error = Some(e),
        }
        if let Some(e) = &meta.error {
            tracing::warn!(list = %c.id, "blocklist not downloaded: {e}");
        }
        let lists = {
            let mut s = lock(&self.state);
            s.lists.insert(c.id.clone(), meta);
            s.lists.clone()
        };
        self.save_meta(&lists);
    }

    /// Compiles the chosen lists when the choice or a download changed.
    fn maybe_compile(&self, settings: &DnsSettings) {
        let chosen = chosen(settings);
        let from: Vec<(String, Option<i64>)> = {
            let s = lock(&self.state);
            chosen
                .iter()
                .map(|c| (c.id.clone(), s.lists.get(&c.id).and_then(|m| m.updated_ms)))
                .collect()
        };
        if lock(&self.state)
            .compiled
            .as_ref()
            .is_some_and(|c| c.from == from)
        {
            return;
        }
        let started = Instant::now();
        let mut domains: Vec<(u16, Vec<String>)> = Vec::new();
        let mut regex = Vec::new();
        let mut names = Vec::new();
        let mut counts = Vec::new();
        for (i, c) in chosen.iter().enumerate() {
            let Ok(text) = std::fs::read_to_string(self.lists_dir().join(format!("{}.txt", c.id)))
            else {
                continue;
            };
            let parsed = parse(&text, c.format);
            counts.push((
                c.id.clone(),
                (parsed.domains.len() + parsed.regexes.len()) as u32,
            ));
            regex.extend(parsed.regexes);
            names.push(dnsconf::ListName {
                id: i as u16,
                name: c.name.clone(),
            });
            domains.push((i as u16, parsed.domains));
        }
        let inputs: Vec<(u16, &[String])> =
            domains.iter().map(|(i, d)| (*i, d.as_slice())).collect();
        let bytes = compile(&inputs, new_key());
        let file = format!("blocklist-{}.w4bl", now_unix_ms());
        let _ = std::fs::create_dir_all(&self.dir);
        if let Err(e) = write_atomic(&self.dir.join(&file), &bytes) {
            lock(&self.state).message = Some(format!("couldn't save the compiled blocklist: {e}"));
            return;
        }
        let compiled_domains = (bytes.len() - w4_dns::compile::HEADER) / 10;
        tracing::info!(
            lists = names.len(),
            domains = compiled_domains,
            regexes = regex.len(),
            ms = started.elapsed().as_millis() as u64,
            "blocklists compiled"
        );
        let mut s = lock(&self.state);
        for (id, n) in counts {
            s.lists.entry(id).or_default().entries = Some(n);
        }
        // Lists no longer chosen: their downloads go, and they're fetched
        // afresh if chosen again.
        let gone: Vec<String> = s
            .lists
            .keys()
            .filter(|id| !chosen.iter().any(|c| &c.id == *id))
            .cloned()
            .collect();
        for id in &gone {
            s.lists.remove(id);
            let _ = std::fs::remove_file(self.lists_dir().join(format!("{id}.txt")));
        }
        if !gone.is_empty() {
            self.save_meta(&s.lists);
        }
        s.compiled = Some(Compiled {
            from,
            file,
            domains: compiled_domains,
            regex,
            names,
        });
    }

    /// Writes the resolver's config when it would change.
    fn write_config(&self, settings: &DnsSettings) {
        let mut servers = system_servers();
        if servers.is_empty() {
            // Keep the last known servers rather than none.
            servers = lock(&self.state)
                .written
                .as_ref()
                .map(|c| c.system_servers.clone())
                .unwrap_or_default();
        }
        let compiled = lock(&self.state).compiled.clone();
        let config = build_config(settings, compiled.as_ref(), servers, captive());
        if lock(&self.state).written.as_ref() == Some(&config) {
            return;
        }
        let Ok(json) = serde_json::to_string_pretty(&config) else {
            return;
        };
        let _ = std::fs::create_dir_all(&self.dir);
        match write_atomic(&self.dir.join(CONFIG_FILE), json.as_bytes()) {
            Ok(()) => {
                tracing::info!(
                    servers = ?config.system_servers,
                    passthrough = config.passthrough,
                    "DNS filtering configuration written"
                );
                lock(&self.state).written = Some(config);
            }
            Err(e) => {
                lock(&self.state).message =
                    Some(format!("couldn't write the resolver's config: {e}"))
            }
        }
    }

    /// Starts the resolver if it isn't running (and restarts it after a crash).
    fn ensure_resolver(&self) {
        let mut s = lock(&self.state);
        if let Some(child) = s.child.as_mut() {
            match child.try_wait() {
                Ok(None) => return,
                Ok(Some(status)) => {
                    tracing::warn!(%status, "the DNS resolver stopped");
                    // Its last words, e.g. port 53 taken by another DNS server.
                    let error = std::fs::read_to_string(self.dir.join("resolver.log"))
                        .ok()
                        .and_then(|t| last_error(&t));
                    if let Some(e) = error {
                        s.message = Some(format!("the resolver stopped: {e}"));
                    }
                    s.child = None;
                    s.restart_after = Some(Instant::now() + RESTART_AFTER);
                }
                Err(e) => tracing::warn!("checking the DNS resolver: {e}"),
            }
        }
        if s.restart_after.is_some_and(|t| Instant::now() < t) || s.written.is_none() {
            return;
        }
        match self.spawn_resolver() {
            Ok(child) => {
                tracing::info!(
                    pid = child.id(),
                    account = child.account(),
                    "DNS resolver started"
                );
                s.child = Some(child);
                s.restart_after = None;
                s.started_ms.get_or_insert(now_unix_ms());
            }
            Err(e) => {
                s.message = Some(format!("can't start {}: {e}", self.resolver_exe.display()));
                s.restart_after = Some(Instant::now() + Duration::from_secs(10));
            }
        }
    }

    fn spawn_resolver(&self) -> std::io::Result<Resolver> {
        let log = std::fs::File::create(self.dir.join("resolver.log"))?;
        let args: [&std::ffi::OsStr; 5] = [
            "console".as_ref(),
            "--dir".as_ref(),
            self.dir.as_os_str(),
            "--pipe".as_ref(),
            self.pipe.as_ref(),
        ];
        match w4_sys::process::spawn_as_local_service(&self.resolver_exe, &args, &log) {
            Ok(p) => return Ok(Resolver::Limited(p)),
            Err(e) if w4_sys::process::not_system(&e) => {}
            Err(e) => tracing::warn!(
                "can't start the DNS resolver as LocalService, so it runs with the service's account: {e}"
            ),
        }
        let err = log.try_clone()?;
        Command::new(&self.resolver_exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(err)
            .creation_flags(NO_WINDOW)
            .spawn()
            .map(Resolver::Plain)
    }

    /// Compiled lists the config no longer names. The resolver may still
    /// have the previous one mapped, which can't go yet; it goes next time.
    fn remove_old_lists(&self) {
        let keep = lock(&self.state)
            .written
            .as_ref()
            .and_then(|c| c.blocklist.clone());
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".w4bl") && Some(&name) != keep.as_ref() {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    fn on_health(&self, healthy: bool) {
        let mut s = lock(&self.state);
        if healthy {
            s.misses = 0;
            s.answers += 1;
            if !s.routed && s.answers >= ANSWERS_TO_ROUTE {
                let loopback = [
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ];
                match w4_sys::nrpt::set(&loopback) {
                    Ok(()) => {
                        tracing::info!("DNS filtering on: Windows' lookups go to the resolver");
                        s.routed = true;
                        s.failed = false;
                        s.message = None;
                    }
                    Err(e) => s.message = Some(e),
                }
            }
            return;
        }
        s.answers = 0;
        s.misses += 1;
        if s.routed && s.misses >= MISSES_TO_RESTORE {
            let removed = w4_sys::nrpt::remove();
            s.routed = false;
            s.failed = true;
            s.restores += 1;
            s.message =
                Some("the resolver stopped answering; Windows' own DNS was put back".into());
            if let Some(mut child) = s.child.take() {
                child.kill();
            }
            s.restart_after = Some(Instant::now() + RESTART_AFTER);
            drop(s);
            match removed {
                Ok(_) => tracing::warn!("DNS resolver not answering: Windows' DNS put back"),
                Err(e) => tracing::error!(
                    "DNS resolver not answering, and the NRPT rule couldn't be removed: {e}"
                ),
            }
            lock(&self.monitor).raise(
                now_unix_ms(),
                None,
                AlertBody::DnsFilter {
                    reason: "it didn't answer for 2 seconds".into(),
                },
            );
        }
    }

    /// The resolver's status and its recent blocked lookups.
    async fn poll_resolver(&self) {
        let status = match w4_ipc::Client::connect(&self.pipe).await {
            Ok(client) => client
                .call::<_, ResolverStatus>(w4_dns::status::method::STATUS, serde_json::Value::Null)
                .await
                .map(|status| (client, status)),
            Err(e) => Err(e),
        };
        let client = match status {
            Ok((client, status)) => {
                let mut s = lock(&self.state);
                s.resolver = Some(status);
                s.unreadable = None;
                client
            }
            Err(e) => {
                let mut s = lock(&self.state);
                if s.unreadable.is_none() {
                    s.unreadable = Some((Instant::now(), e.to_string()));
                }
                return;
            }
        };
        let after = lock(&self.state).last_log_id;
        if let Ok(log) = client
            .call::<_, LogResult>(
                w4_dns::status::method::LOG,
                LogParams {
                    after,
                    limit: Some(5_000),
                },
            )
            .await
        {
            let now = now_unix_ms();
            let mut blocked = lock(&self.blocked);
            for e in &log.entries {
                if e.outcome == w4_dns::status::Outcome::Blocked {
                    blocked.insert(
                        e.name.clone(),
                        (e.reason.clone().unwrap_or_default(), e.ts_ms),
                    );
                }
            }
            blocked.retain(|_, (_, ts)| now - *ts < BLOCKED_NAMES_KEEP_MS);
            if blocked.len() > MAX_BLOCKED_NAMES {
                let mut by_age: Vec<_> =
                    blocked.iter().map(|(n, (_, t))| (*t, n.clone())).collect();
                by_age.sort();
                for (_, n) in by_age.into_iter().take(blocked.len() - MAX_BLOCKED_NAMES) {
                    blocked.remove(&n);
                }
            }
            if let Some(last) = log.entries.last() {
                lock(&self.state).last_log_id = last.id;
            }
        }
    }

    /// What blocked `name` around `ts_ms`, for the DNS log.
    pub fn blocked_by(&self, name: &str, ts_ms: i64) -> Option<String> {
        let blocked = lock(&self.blocked);
        let (why, at) = blocked.get(&name.to_ascii_lowercase())?;
        ((ts_ms - at).abs() < 60_000).then(|| why.clone())
    }

    pub fn update_now(&self) {
        self.force_update.store(true, Ordering::Relaxed);
    }

    /// The resolver's recent lookups, for the app.
    pub async fn log(&self, after: u64, limit: usize) -> Vec<DnsFilterLogEntry> {
        let Ok(client) = w4_ipc::Client::connect(&self.pipe).await else {
            return Vec::new();
        };
        let Ok(log) = client
            .call::<_, LogResult>(
                w4_dns::status::method::LOG,
                LogParams {
                    after,
                    limit: Some(limit),
                },
            )
            .await
        else {
            return Vec::new();
        };
        log.entries
            .into_iter()
            .map(|e| DnsFilterLogEntry {
                id: e.id,
                ts_ms: e.ts_ms,
                name: e.name,
                qtype: e.qtype,
                outcome: serde_json::to_value(e.outcome)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                reason: e.reason,
                upstream_ms: e.upstream_ms,
            })
            .collect()
    }

    pub fn status(&self) -> DnsFilterStatus {
        let settings = self.settings();
        let s = lock(&self.state);
        let resolver = s.resolver.as_ref();
        let paused = settings.paused_until_ms.filter(|t| *t > now_unix_ms());
        let state = if !settings.enabled {
            DnsFilterState::Off
        } else if s.failed && !s.routed {
            DnsFilterState::Failed
        } else if !s.routed {
            DnsFilterState::Starting
        } else if paused.is_some() || resolver.is_some_and(|r| r.observing || r.passthrough) {
            DnsFilterState::Passing
        } else {
            DnsFilterState::On
        };
        let message = s.message.clone().or_else(|| match state {
            DnsFilterState::Passing if paused.is_some() => Some("blocking is paused".into()),
            DnsFilterState::Passing if resolver.is_some_and(|r| r.passthrough) => {
                Some("a sign-in page: lookups pass unfiltered until the network is online".into())
            }
            DnsFilterState::Passing => {
                Some("only observing: your network's DNS already blocks ads".into())
            }
            DnsFilterState::Starting if s.compiled.is_none() => {
                Some("downloading the blocklists".into())
            }
            DnsFilterState::Starting => Some("starting the resolver".into()),
            _ => None,
        });
        let chosen_ids: Vec<String> = chosen(&settings).into_iter().map(|c| c.id).collect();
        let mut lists: Vec<DnsListState> = catalogue::LISTS
            .iter()
            .map(|e| {
                let meta = s.lists.get(e.id);
                DnsListState {
                    id: e.id.into(),
                    name: e.name.into(),
                    description: e.description.into(),
                    url: e.url.into(),
                    homepage: e.homepage.into(),
                    licence: e.licence.into(),
                    licence_url: e.licence_url.into(),
                    enabled: chosen_ids.iter().any(|c| c == e.id),
                    custom: false,
                    entries: meta.and_then(|m| m.entries),
                    updated_ms: meta.and_then(|m| m.updated_ms),
                    error: meta.and_then(|m| m.error.clone()),
                }
            })
            .collect();
        for c in &settings.custom_lists {
            let id = custom_id(c);
            let meta = s.lists.get(&id);
            lists.push(DnsListState {
                id: id.clone(),
                name: c.name.clone(),
                description: if c.regex {
                    "Your list (regex)".into()
                } else {
                    "Your list".into()
                },
                url: c.url.clone(),
                homepage: c.url.clone(),
                licence: String::new(),
                licence_url: String::new(),
                enabled: true,
                custom: true,
                entries: meta.and_then(|m| m.entries),
                updated_ms: meta.and_then(|m| m.updated_ms),
                error: meta.and_then(|m| m.error.clone()),
            });
        }
        DnsFilterStatus {
            state: Some(state),
            message,
            routed: s.routed,
            lists,
            blocked_domains: s.compiled.as_ref().map_or(0, |c| c.domains),
            upstream: match &settings.upstream {
                DnsUpstream::System => "your network's DNS servers".into(),
                DnsUpstream::Doh { url } => url.clone(),
            },
            system_servers: s
                .written
                .as_ref()
                .map(|c| c.system_servers.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            upstream_blocks: resolver.and_then(|r| r.upstream_blocks),
            queries: resolver.map_or(0, |r| r.counters.queries),
            blocked: resolver.map_or(0, |r| r.counters.blocked),
            cached: resolver.map_or(0, |r| r.counters.cached),
            top_blocked: resolver.map(|r| r.top_blocked.clone()).unwrap_or_default(),
            problems: resolver
                .map(|r| r.problems.clone())
                .unwrap_or_default()
                .into_iter()
                .chain(
                    s.unreadable
                        .as_ref()
                        .filter(|(since, _)| s.routed && since.elapsed() >= UNREADABLE_AFTER)
                        .map(|(_, e)| {
                            format!(
                                "Can't read the resolver's counts and log ({e}); it's still filtering"
                            )
                        }),
                )
                .collect(),
            restores: s.restores,
            resolver_account: s.child.as_ref().map(|c| c.account().to_string()),
            last_update_ms: s.last_update_ms,
            paused_until_ms: paused,
        }
    }
}

/// Settings that can't work, as the user should read it.
pub fn check(s: &DnsSettings) -> Result<(), String> {
    for id in &s.lists {
        if catalogue::find(id).is_none() {
            return Err(format!("no blocklist {id:?} in the catalogue"));
        }
    }
    for (i, c) in s.custom_lists.iter().enumerate() {
        if !c.url.starts_with("https://") {
            return Err(format!("{}: only https:// lists", c.name));
        }
        if s.custom_lists[..i].iter().any(|o| o.url == c.url) {
            return Err(format!("{} is already one of your lists", c.url));
        }
    }
    if let DnsUpstream::Doh { url } = &s.upstream
        && !url.starts_with("https://")
    {
        return Err("DNS over HTTPS needs an https:// address".into());
    }
    if s.regex.len() > w4_dns::rules::MAX_REGEXES {
        return Err(format!(
            "at most {} regex rules",
            w4_dns::rules::MAX_REGEXES
        ));
    }
    for r in &s.regex {
        regex_check(r)?;
    }
    for n in s.allow.iter().chain(&s.deny) {
        if w4_dns::normalize(n).is_none() {
            return Err(format!("{n:?} isn't a domain name"));
        }
    }
    for r in &s.local_records {
        if w4_dns::normalize(&r.name).is_none() || r.addrs.is_empty() {
            return Err(format!(
                "local record {:?} needs a name and an address",
                r.name
            ));
        }
    }
    Ok(())
}

/// The error a program ended with: Rust prints `Error: …` last, then any
/// causes on the lines after it.
fn last_error(log: &str) -> Option<String> {
    let lines: Vec<&str> = log.lines().collect();
    let start = lines.iter().rposition(|l| l.starts_with("Error: "))?;
    let parts: Vec<&str> = lines[start..]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && *l != "Caused by:")
        .collect();
    Some(parts.join(": ").trim_start_matches("Error: ").to_string())
}

fn regex_check(pattern: &str) -> Result<(), String> {
    let (_, problems) =
        w4_dns::rules::Rules::new(Vec::new(), Vec::new(), vec![pattern.to_string()]);
    match problems.into_iter().next() {
        Some(p) => Err(p),
        None => Ok(()),
    }
}

/// One health check: the resolver's own name, straight to 127.0.0.1:53.
async fn health_check() -> bool {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
        return false;
    };
    let id = w4_sys::random::u16();
    let Ok(query) = wire::query(id, HEALTH_NAME, wire::TYPE_A) else {
        return false;
    };
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    if socket.send_to(&query, server).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    match tokio::time::timeout(HEALTH_TIMEOUT, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => wire::parse_answer(&buf[..n]).is_ok_and(|a| a.id == id && a.rcode == 0),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_checked() {
        let mut s = DnsSettings::default();
        assert!(check(&s).is_ok());
        s.lists.push("nope".into());
        assert!(check(&s).is_err());
        s.lists.pop();
        s.deny.push("not a name".into());
        assert!(check(&s).is_err());
        s.deny.clear();
        s.regex.push("(unclosed".into());
        assert!(check(&s).is_err());
        s.regex.clear();
        s.upstream = DnsUpstream::Doh {
            url: "http://x".into(),
        };
        assert!(check(&s).is_err());
        s.upstream = DnsUpstream::System;
        let list = CustomList {
            name: "mine".into(),
            url: "https://a.example/l.txt".into(),
            regex: false,
        };
        s.custom_lists = vec![list.clone(), list];
        assert!(check(&s).is_err());
    }

    #[test]
    fn the_config_follows_the_settings() {
        let s = DnsSettings {
            nxdomain: true,
            deny: vec!["ads.example.com".into()],
            upstream: DnsUpstream::Doh {
                url: "https://dns.quad9.net/dns-query".into(),
            },
            ..DnsSettings::default()
        };
        let c = build_config(&s, None, vec!["192.168.1.1".parse().unwrap()], true);
        assert_eq!(c.block_answer, dnsconf::BlockAnswer::Nxdomain);
        assert!(c.passthrough);
        assert_eq!(c.deny, ["ads.example.com"]);
        assert!(matches!(c.upstream, dnsconf::Upstream::Doh { .. }));
        assert_eq!(c.blocklist, None);
    }

    #[test]
    fn the_resolver_s_last_error_is_found() {
        let log = "2026-10-26 INFO resolver starting
Error: binding the DNS ports

Caused by:
    127.0.0.1:53 is already in use
";
        assert_eq!(
            last_error(log).as_deref(),
            Some("binding the DNS ports: 127.0.0.1:53 is already in use")
        );
        assert_eq!(
            last_error(
                "2026-10-26 INFO all fine
"
            ),
            None
        );
    }

    #[test]
    fn custom_lists_keep_their_ids() {
        let list = |url: &str| CustomList {
            name: "mine".into(),
            url: url.into(),
            regex: false,
        };
        let mut s = DnsSettings {
            lists: Vec::new(),
            custom_lists: vec![
                list("https://a.example/1.txt"),
                list("https://b.example/2.txt"),
            ],
            ..DnsSettings::default()
        };
        let second = chosen(&s)[1].id.clone();
        s.custom_lists.remove(0);
        assert_eq!(chosen(&s)[0].id, second);
        assert_ne!(custom_id(&list("https://a.example/1.txt")), second);
    }
}
