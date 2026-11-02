//! One lookup, start to finish (SPEC §13): the health name and local records
//! answered here; a sign-in page passed through; allow, deny, regex and the
//! blocklists; the cache; upstream (system servers for local names and the
//! DoH server's own name); then the answer's CNAMEs checked too.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use w4_dns::config::{FIREFOX_CANARY, HEALTH_NAME, Observe, Upstream, is_local_name};
use w4_dns::rules::{Verdict, Why};
use w4_dns::wire::{self, BlockAnswer, RData};

use crate::cache::Cache;
use crate::journal::{Entry, Journal, Outcome};
use crate::state::{Current, Loaded};
use crate::upstream::{self, Doh};

/// Whether the upstream already blocks ads (an ad-blocking DNS server): unknown, no, yes.
const UNKNOWN: u8 = 0;
const NO: u8 = 1;
const YES: u8 = 2;
/// Names a filtering upstream answers with a null address or NXDOMAIN.
const PROBES: &[&str] = &["doubleclick.net", "googleadservices.com"];

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

pub struct Resolver {
    pub current: Current,
    pub cache: Cache,
    pub journal: Journal,
    doh: Mutex<Option<Arc<Doh>>>,
    upstream_blocks: AtomicU8,
}

fn why_text(s: &Loaded, why: &Why) -> (String, String) {
    match why {
        Why::Deny(rule) => ("Deny rules".into(), format!("your deny rule {rule}")),
        Why::Regex(i) => (
            "Regex rules".into(),
            format!("regex {}", s.rules.pattern(*i).unwrap_or("?")),
        ),
        Why::List(id, listed) => {
            let list = s
                .list_names
                .get(id)
                .cloned()
                .unwrap_or_else(|| format!("list {id}"));
            (list.clone(), format!("{list}: {listed}"))
        }
    }
}

fn null_answer(a: &wire::Answer) -> bool {
    a.answers.iter().any(|r| match r.data {
        RData::A(v4) => v4.is_unspecified(),
        RData::Aaaa(v6) => v6.is_unspecified(),
        _ => false,
    })
}

impl Resolver {
    pub fn new(current: Current) -> Resolver {
        Resolver {
            current,
            cache: Cache::default(),
            journal: Journal::default(),
            doh: Mutex::new(None),
            upstream_blocks: AtomicU8::new(UNKNOWN),
        }
    }

    /// The DoH client for the configured URL, made anew when it changes.
    fn doh(&self, s: &Loaded) -> Option<Arc<Doh>> {
        let Upstream::Doh { url } = &s.config.upstream else {
            *self.doh.lock().unwrap_or_else(|p| p.into_inner()) = None;
            return None;
        };
        let mut slot = self.doh.lock().unwrap_or_else(|p| p.into_inner());
        if slot
            .as_ref()
            .is_none_or(|d| Some(d.host()) != s.doh_host.as_deref())
        {
            *slot = Doh::new(url).ok().map(Arc::new);
        }
        slot.clone()
    }

    pub fn close_idle(&self) {
        if let Some(d) = self.doh.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            d.close_if_idle();
        }
    }

    pub fn upstream_blocks(&self) -> Option<bool> {
        match self.upstream_blocks.load(Ordering::Relaxed) {
            YES => Some(true),
            NO => Some(false),
            _ => None,
        }
    }

    /// Asks the upstream about well-known ad names: a null answer means it
    /// filters already (SPEC §13 "A blocking DNS server already present").
    pub async fn probe_upstream(&self) {
        let s = self.current.get();
        let mut nulls = 0;
        let mut asked = 0;
        for name in PROBES {
            let Ok(q) = wire::query(w4_sys::random::u16(), name, wire::TYPE_A) else {
                continue;
            };
            if let Ok((answer, _)) = self.forward(&s, name, &q).await
                && let Ok(a) = wire::parse_answer(&answer)
            {
                asked += 1;
                if null_answer(&a) || a.rcode == wire::RCODE_NXDOMAIN {
                    nulls += 1;
                }
            }
        }
        if asked > 0 {
            let blocks = nulls == asked;
            let before = self
                .upstream_blocks
                .swap(if blocks { YES } else { NO }, Ordering::Relaxed);
            if before != (if blocks { YES } else { NO }) {
                tracing::info!(
                    upstream_blocks = blocks,
                    "upstream checked for its own filtering"
                );
            }
        }
    }

    async fn forward(
        &self,
        s: &Loaded,
        name: &str,
        query: &[u8],
    ) -> Result<(Vec<u8>, Option<IpAddr>), String> {
        let system = || upstream::system(&s.config.system_servers, query);
        let to_system = matches!(s.config.upstream, Upstream::System)
            || is_local_name(name, &s.config.local_suffixes)
            || s.doh_host.as_deref() == Some(name);
        if to_system {
            return system().await.map(|(a, ip)| (a, Some(ip)));
        }
        let Some(doh) = self.doh(s) else {
            return system().await.map(|(a, ip)| (a, Some(ip)));
        };
        let q = query.to_vec();
        tokio::task::spawn_blocking(move || doh.ask(&q))
            .await
            .map_err(|e| e.to_string())?
            .map(|a| (a, None))
    }

    fn entry(
        &self,
        q: &wire::Query,
        outcome: Outcome,
        reason: Option<String>,
        upstream_ms: Option<u32>,
        rcode: u8,
    ) -> Entry {
        Entry {
            id: 0,
            ts_ms: now_ms(),
            name: q.question.name.clone(),
            qtype: q.question.qtype,
            outcome,
            reason,
            upstream_ms,
            rcode,
        }
    }

    fn block(
        &self,
        s: &Loaded,
        query: &[u8],
        q: &wire::Query,
        kind: &str,
        reason: String,
    ) -> Vec<u8> {
        let how = match s.config.block_answer {
            w4_dns::config::BlockAnswer::NullIp => BlockAnswer::NullIp,
            w4_dns::config::BlockAnswer::Nxdomain => BlockAnswer::Nxdomain,
        };
        let answer = wire::blocked(query, q, how);
        let rcode = if how == BlockAnswer::Nxdomain {
            wire::RCODE_NXDOMAIN
        } else {
            wire::RCODE_NOERROR
        };
        self.journal.record(
            self.entry(q, Outcome::Blocked, Some(reason), None, rcode),
            Some(kind),
        );
        answer
    }

    /// The answer to one query, or `None` for something that isn't one.
    pub async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q = wire::parse_query(query).ok()?;
        let name = q.question.name.clone();
        tracing::debug!(%name, qtype = q.question.qtype, "query");
        if name == HEALTH_NAME {
            let addrs = [
                IpAddr::from([127, 0, 0, 1]),
                IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
            ];
            return Some(wire::local(query, &q, &addrs));
        }
        let s = self.current.get();
        let unfiltered = s.config.passthrough || !q.standard || q.question.qclass != wire::CLASS_IN;
        if unfiltered {
            let t = Instant::now();
            return Some(
                match upstream::system(&s.config.system_servers, query).await {
                    Ok((answer, _)) => {
                        let rcode = wire::parse_answer(&answer).map_or(0, |a| a.rcode);
                        let ms = Some(t.elapsed().as_millis() as u32);
                        self.journal
                            .record(self.entry(&q, Outcome::Passed, None, ms, rcode), None);
                        answer
                    }
                    Err(e) => {
                        self.journal.record(
                            self.entry(&q, Outcome::Failed, Some(e), None, wire::RCODE_SERVFAIL),
                            None,
                        );
                        wire::error(query, &q, wire::RCODE_SERVFAIL)
                    }
                },
            );
        }
        if let Some(addrs) = s.local.get(&name) {
            self.journal
                .record(self.entry(&q, Outcome::Local, None, None, 0), None);
            return Some(wire::local(query, &q, addrs));
        }
        let paused = s.config.paused_until_ms.is_some_and(|t| now_ms() < t);
        let filtering = s.config.filtering && !paused;
        let observe = match s.config.observe {
            Observe::On => true,
            Observe::Off => false,
            Observe::Auto => self.upstream_blocks() == Some(true),
        };
        if filtering && !observe && name == FIREFOX_CANARY {
            let answer = wire::blocked(query, &q, BlockAnswer::Nxdomain);
            self.journal.record(
                self.entry(
                    &q,
                    Outcome::Blocked,
                    Some("Firefox canary: keeps Firefox on this resolver".into()),
                    None,
                    wire::RCODE_NXDOMAIN,
                ),
                Some("Firefox canary"),
            );
            return Some(answer);
        }
        let verdict = if filtering {
            s.rules.decide(&name, s.blocklist.as_ref())
        } else {
            Verdict::Pass
        };
        let mut would_block = None;
        let mut allowed = None;
        match verdict {
            Verdict::Blocked(why) => {
                let (kind, reason) = why_text(&s, &why);
                if !observe {
                    return Some(self.block(&s, query, &q, &kind, reason));
                }
                would_block = Some(reason);
            }
            Verdict::Allowed { rule } => allowed = Some(format!("your allow rule {rule}")),
            Verdict::Pass => {}
        }
        if let Some(hit) = self.cache.get(&q.question, q.id) {
            let outcome = if would_block.is_some() {
                Outcome::WouldBlock
            } else {
                Outcome::Cached
            };
            self.journal
                .record(self.entry(&q, outcome, would_block, None, 0), None);
            return Some(hit);
        }
        let t = Instant::now();
        let (answer, _) = match self.forward(&s, &name, query).await {
            Ok(a) => a,
            Err(e) => {
                self.journal.record(
                    self.entry(&q, Outcome::Failed, Some(e), None, wire::RCODE_SERVFAIL),
                    None,
                );
                return Some(wire::error(query, &q, wire::RCODE_SERVFAIL));
            }
        };
        let upstream_ms = Some(t.elapsed().as_millis() as u32);
        let parsed = wire::parse_answer(&answer).ok();
        // CNAME inspection: a blocked name behind an alias is blocked too.
        if filtering
            && !observe
            && allowed.is_none()
            && let Some(a) = &parsed
        {
            for r in &a.answers {
                if let RData::Cname(target) = &r.data
                    && let Verdict::Blocked(why) = s.rules.decide(target, s.blocklist.as_ref())
                {
                    let (kind, reason) = why_text(&s, &why);
                    return Some(self.block(
                        &s,
                        query,
                        &q,
                        &kind,
                        format!("CNAME {target} ({reason})"),
                    ));
                }
            }
        }
        let rcode = parsed.as_ref().map_or(0, |a| a.rcode);
        let outcome = if would_block.is_some() {
            Outcome::WouldBlock
        } else if allowed.is_some() {
            Outcome::Allowed
        } else if parsed.as_ref().is_some_and(null_answer) {
            Outcome::BlockedUpstream
        } else {
            Outcome::Answered
        };
        self.cache.put(&q.question, &answer);
        self.journal.record(
            self.entry(&q, outcome, would_block.or(allowed), upstream_ms, rcode),
            None,
        );
        Some(answer)
    }
}
