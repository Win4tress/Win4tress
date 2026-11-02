//! Answers kept for their time to live (at most an hour), so a repeat lookup
//! costs microseconds; TTLs are counted down when served. Bounded: when full,
//! expired answers go first, then the oldest.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use w4_dns::wire;

const MAX_ENTRIES: usize = 10_000;
const MAX_TTL: u32 = 3600;
/// NXDOMAIN answers are kept this long.
const NEGATIVE_TTL: u32 = 60;

type Key = (String, u16, u16);

struct Entry {
    answer: Vec<u8>,
    stored: Instant,
    ttl: Duration,
}

#[derive(Default)]
pub struct Cache {
    entries: Mutex<(HashMap<Key, Entry>, VecDeque<Key>)>,
}

impl Cache {
    fn key(q: &wire::Question) -> Key {
        (q.name.clone(), q.qtype, q.qclass)
    }

    /// The cached answer for `q`, with `id` and aged TTLs.
    pub fn get(&self, q: &wire::Question, id: u16) -> Option<Vec<u8>> {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let key = Self::key(q);
        let entry = guard.0.get(&key)?;
        let age = entry.stored.elapsed();
        if age >= entry.ttl {
            guard.0.remove(&key);
            return None;
        }
        let mut answer = wire::with_id(&entry.answer, id);
        wire::age_ttls(&mut answer, age.as_secs() as u32);
        Some(answer)
    }

    /// Keeps a successful answer (records, or NXDOMAIN) for its TTL.
    pub fn put(&self, q: &wire::Question, answer: &[u8]) {
        let Ok(parsed) = wire::parse_answer(answer) else {
            return;
        };
        let ttl = match parsed.rcode {
            wire::RCODE_NOERROR => match wire::min_ttl(&parsed) {
                Some(t) if t > 0 => t.min(MAX_TTL),
                _ => return,
            },
            wire::RCODE_NXDOMAIN => NEGATIVE_TTL,
            _ => return,
        };
        if parsed.truncated {
            return;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let (map, order) = &mut *guard;
        if map.len() >= MAX_ENTRIES {
            map.retain(|_, e| e.stored.elapsed() < e.ttl);
            order.retain(|k| map.contains_key(k));
            while map.len() >= MAX_ENTRIES {
                let Some(old) = order.pop_front() else { break };
                map.remove(&old);
            }
        }
        let key = Self::key(q);
        if !map.contains_key(&key) {
            order.push_back(key.clone());
        }
        map.insert(
            key,
            Entry {
                answer: answer.to_vec(),
                stored: Instant::now(),
                ttl: Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .len()
    }

    pub fn clear(&self) {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        guard.0.clear();
        guard.1.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_come_back_with_the_new_id() {
        let cache = Cache::default();
        let q = wire::query(1, "ads.example.com", wire::TYPE_A).unwrap();
        let p = wire::parse_query(&q).unwrap();
        let answer = wire::blocked(&q, &p, wire::BlockAnswer::NullIp);
        cache.put(&p.question, &answer);
        let hit = cache.get(&p.question, 99).unwrap();
        assert_eq!(wire::parse_answer(&hit).unwrap().id, 99);
        assert_eq!(cache.len(), 1);
        // SERVFAIL isn't kept.
        let other = wire::query(2, "x.example.com", wire::TYPE_A).unwrap();
        let po = wire::parse_query(&other).unwrap();
        cache.put(
            &po.question,
            &wire::error(&other, &po, wire::RCODE_SERVFAIL),
        );
        assert!(cache.get(&po.question, 2).is_none());
    }
}
