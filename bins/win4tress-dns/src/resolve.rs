//! One lookup, start to finish (SPEC §13): the health name and local records
//! answered here; a sign-in page passed through; allow, deny, regex and the
//! blocklists; the cache; upstream (system servers for local names and the
//! DoH server's own name); then the answer's CNAMEs checked too. A one-label
//! or `.local` name the servers don't know is looked for on the local network,
//! as Windows would without the routing rule, in pass-through too. If nothing
//! there has it either, "no such name" is kept only seconds, here and by
//! Windows: just after a wake the network may not be up yet.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::OnceCell;

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
/// How long a name's addresses on the local network are kept.
const NEARBY_TTL: Duration = Duration::from_secs(30);
/// How long a name nothing on the local network has stays unknown, here and
/// in Windows' cache (the TTL of the "no such name" answer).
const MISS_SECS: u32 = 5;

/// A name's addresses on the local network: looked for once, shared by every
/// lookup of it meanwhile (Windows asks for A and AAAA at once, and again).
type Nearby = Arc<OnceCell<Vec<IpAddr>>>;

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
    nearby: Mutex<HashMap<String, (Instant, Nearby)>>,
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

/// A lookup Windows would also try on the local network: A or AAAA for a
/// one-label or `.local` name.
fn nearby_name(q: &wire::Query) -> bool {
    q.standard
        && q.question.qclass == wire::CLASS_IN
        && matches!(q.question.qtype, wire::TYPE_A | wire::TYPE_AAAA)
        && w4_sys::localname::is_multicast_name(&q.question.name)
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
            nearby: Mutex::new(HashMap::new()),
        }
    }

    /// `name`'s addresses on the local network (LLMNR, mDNS), IPv4 and IPv6.
    async fn on_local_network(&self, name: &str) -> Vec<IpAddr> {
        let cell = {
            let mut map = self.nearby.lock().unwrap_or_else(|p| p.into_inner());
            map.retain(|_, (t, cell)| {
                let keep = match cell.get() {
                    Some(addrs) if addrs.is_empty() => Duration::from_secs(MISS_SECS.into()),
                    _ => NEARBY_TTL,
                };
                t.elapsed() < keep
            });
            map.entry(name.to_string())
                .or_insert_with(|| (Instant::now(), Nearby::default()))
                .1
                .clone()
        };
        cell.get_or_init(|| async {
            let (v4, v6) = (name.to_string(), name.to_string());
            let (v4, v6) = tokio::join!(
                tokio::task::spawn_blocking(move || w4_sys::localname::lookup(&v4, false)),
                tokio::task::spawn_blocking(move || w4_sys::localname::lookup(&v6, true)),
            );
            let mut all = v4.unwrap_or_default();
            all.extend(v6.unwrap_or_default());
            all
        })
        .await
        .clone()
    }

    /// For a one-label or `.local` A or AAAA lookup the servers couldn't
    /// answer, the answer from the local network, if anything there has the name.
    async fn nearby_answer(
        &self,
        query: &[u8],
        q: &wire::Query,
        upstream_ms: Option<u32>,
    ) -> Option<Vec<u8>> {
        if !nearby_name(q) {
            return None;
        }
        let name = &q.question.name;
        let addrs = self.on_local_network(name).await;
        tracing::debug!(%name, found = addrs.len(), "looked for on the local network");
        if addrs.is_empty() {
            return None;
        }
        self.journal.record(
            self.entry(
                q,
                Outcome::Local,
                Some("found on the local network".into()),
                upstream_ms,
                wire::RCODE_NOERROR,
            ),
            None,
        );
        // Only the asked family; none of it is an empty answer, not NXDOMAIN.
        Some(wire::local(query, q, &addrs))
    }

    /// The servers didn't answer: the local network's answer, or SERVFAIL.
    async fn failed(&self, query: &[u8], q: &wire::Query, e: String) -> Vec<u8> {
        if let Some(answer) = self.nearby_answer(query, q, None).await {
            return answer;
        }
        self.journal.record(
            self.entry(q, Outcome::Failed, Some(e), None, wire::RCODE_SERVFAIL),
            None,
        );
        wire::error(query, q, wire::RCODE_SERVFAIL)
    }

    /// Drops what was learnt on the network before (the config changes with
    /// it): cached answers and what the local network had.
    pub fn forget(&self) {
        self.cache.clear();
        self.nearby
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
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
            let (mut answer, _) = match upstream::system(&s.config.system_servers, query).await {
                Ok(a) => a,
                Err(e) => return Some(self.failed(query, &q, e).await),
            };
            let ms = Some(t.elapsed().as_millis() as u32);
            let rcode = wire::parse_answer(&answer).map_or(0, |a| a.rcode);
            if rcode == wire::RCODE_NXDOMAIN && nearby_name(&q) {
                if let Some(found) = self.nearby_answer(query, &q, ms).await {
                    return Some(found);
                }
                answer = wire::brief_nxdomain(query, &q, MISS_SECS);
            }
            self.journal
                .record(self.entry(&q, Outcome::Passed, None, ms, rcode), None);
            return Some(answer);
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
        let (mut answer, _) = match self.forward(&s, &name, query).await {
            Ok(a) => a,
            Err(e) => return Some(self.failed(query, &q, e).await),
        };
        let upstream_ms = Some(t.elapsed().as_millis() as u32);
        let parsed = wire::parse_answer(&answer).ok();
        // Not cached: the local network is asked again next time.
        let missing = nearby_name(&q)
            && parsed
                .as_ref()
                .is_some_and(|a| a.rcode == wire::RCODE_NXDOMAIN);
        if missing {
            if let Some(found) = self.nearby_answer(query, &q, upstream_ms).await {
                return Some(found);
            }
            answer = wire::brief_nxdomain(query, &q, MISS_SECS);
        }
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
        if !missing {
            self.cache.put(&q.question, &answer);
        }
        self.journal.record(
            self.entry(&q, outcome, would_block.or(allowed), upstream_ms, rcode),
            None,
        );
        Some(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver whose config file is `json`, in a folder of its own.
    fn resolver(json: &str) -> Resolver {
        let dir = std::env::temp_dir().join(format!("w4-resolve-{}", w4_sys::random::u16()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), json).unwrap();
        Resolver::new(Current::new(dir))
    }

    #[test]
    fn nearby_names_are_one_label_or_local_addresses() {
        let q =
            |name: &str, qtype| wire::parse_query(&wire::query(1, name, qtype).unwrap()).unwrap();
        assert!(nearby_name(&q("garrserver", wire::TYPE_A)));
        assert!(nearby_name(&q("printer.local", wire::TYPE_AAAA)));
        assert!(!nearby_name(&q("garrserver", wire::TYPE_HTTPS)));
        assert!(!nearby_name(&q("example.com", wire::TYPE_A)));
    }

    /// Needs the network and a named computer on it:
    /// `$env:W4_LOCAL_NAME = "garrserver"; cargo test -p win4tress-dns nearby -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "needs a named computer on the local network"]
    async fn a_local_name_dns_doesn_t_know_is_found_nearby() {
        let name = std::env::var("W4_LOCAL_NAME").expect("W4_LOCAL_NAME");
        // Pass-through too: what a sign-in page, or a wake, switches to.
        for passthrough in [false, true] {
            let r = resolver(&format!(
                r#"{{"system_servers":["1.1.1.1"],"passthrough":{passthrough}}}"#
            ));
            for qtype in [wire::TYPE_A, wire::TYPE_AAAA] {
                let q = wire::query(1, &name, qtype).unwrap();
                let a = wire::parse_answer(&r.answer(&q).await.unwrap()).unwrap();
                println!(
                    "passthrough {passthrough}, {name} type {qtype}: rcode {} answers {}",
                    a.rcode,
                    a.answers.len()
                );
                // Found: an answer, even one with no records of the family asked for.
                assert_eq!(a.rcode, wire::RCODE_NOERROR);
            }
            let none = wire::query(2, "w4-no-such-host-7f3a91", wire::TYPE_A).unwrap();
            let answer = r.answer(&none).await.unwrap();
            assert_eq!(
                wire::parse_answer(&answer).unwrap().rcode,
                wire::RCODE_NXDOMAIN
            );
            // Kept seconds by Windows (the SOA's minimum ends the message), not here.
            assert!(answer.ends_with(&MISS_SECS.to_be_bytes()));
            assert_eq!(r.cache.len(), 0);
        }
    }
}
