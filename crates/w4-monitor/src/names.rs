//! Hostnames: from each app's own DNS lookups first, then any app's, then reverse
//! DNS. Each map is capped, oldest entries dropped first.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;

use w4_ipc::api::AppId;

const MAX_NAMES: usize = 50_000;

struct Capped<K> {
    map: HashMap<K, String>,
    order: VecDeque<K>,
}

impl<K> Default for Capped<K> {
    fn default() -> Self {
        Capped {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<K: Copy + Eq + Hash> Capped<K> {
    fn insert(&mut self, key: K, name: &str) {
        if self.map.insert(key, name.to_string()).is_none() {
            self.order.push_back(key);
            if self.order.len() > MAX_NAMES
                && let Some(old) = self.order.pop_front()
            {
                self.map.remove(&old);
            }
        }
    }

    fn get(&self, key: &K) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }
}

#[derive(Default)]
pub struct Names {
    by_app: Capped<(AppId, IpAddr)>,
    global: Capped<IpAddr>,
    reverse: Capped<IpAddr>,
}

impl Names {
    /// A name an app got back from its own DNS lookup.
    pub fn insert(&mut self, app: AppId, ip: IpAddr, name: &str) {
        self.by_app.insert((app, ip), name);
        self.global.insert(ip, name);
    }

    /// A PTR name, used only when no app looked the address up.
    pub fn insert_reverse(&mut self, ip: IpAddr, name: &str) {
        self.reverse.insert(ip, name);
    }

    /// The name this app looked up for `ip`, else any app's, else reverse DNS.
    pub fn get(&self, app: AppId, ip: IpAddr) -> Option<&str> {
        self.by_app
            .get(&(app, ip))
            .or_else(|| self.global.get(&ip))
            .or_else(|| self.reverse.get(&ip))
    }

    pub fn has_any(&self, ip: IpAddr) -> bool {
        self.global.get(&ip).is_some() || self.reverse.get(&ip).is_some()
    }
}
