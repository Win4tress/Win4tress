//! Ask to Connect's prompts (SPEC §7.4). An app blocked by Windows Firewall's
//! default (no rule allowed it) becomes a question for the user: at most one
//! per app at a time and five shown a minute, the rest waiting their turn. A
//! prompt not answered within a minute stays as "pending" and the app stays
//! blocked. Microsoft-signed system programs are allowed without asking,
//! except the tools malware abuses.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use w4_core::ask::{abused_tools, allowed_without_asking};
use w4_core::firewall::{Action, Direction, Expiry, Mode, Origin, RuleId, Scope};
use w4_core::time::now_unix_ms;
use w4_ipc::Notification;
use w4_ipc::api::{
    AppId, Decision, DecisionScope, Prompt, PromptState, PromptsResult, notification,
};
use w4_monitor::Monitor;
use w4_store::{NewRule, Store};

use crate::enforcer::{Enforcer, target_of};

/// Prompts shown per minute, overall; more wait their turn.
pub const SHOWN_PER_MINUTE: usize = 5;
/// An open prompt not answered in this long becomes pending.
pub const OPEN_FOR_MS: i64 = 60_000;
const MINUTE_MS: i64 = 60_000;
/// How often waiting prompts are opened and open ones timed out.
const TICK: Duration = Duration::from_secs(1);

/// One outgoing attempt Windows Firewall's default blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub app: AppId,
    pub remote: SocketAddr,
    pub ts_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: u64,
    pub app: AppId,
    /// The first attempt's destination.
    pub remote: SocketAddr,
    pub attempts: u32,
    pub first_ms: i64,
    pub last_ms: i64,
    pub state: PromptState,
    /// When it was shown.
    opened_ms: Option<i64>,
}

/// The prompts and the rate limit (pure, so the rules can be tested).
#[derive(Default)]
pub struct Queue {
    next_id: u64,
    entries: Vec<Entry>,
    /// When prompts were shown in the last minute.
    shown: VecDeque<i64>,
}

impl Queue {
    /// Counts an attempt against the app's prompt, or makes one. Returns
    /// whether a prompt was made (more attempts aren't worth announcing).
    pub fn attempt(&mut self, a: Attempt) -> bool {
        if let Some(e) = self.entries.iter_mut().find(|e| e.app == a.app) {
            e.attempts += 1;
            e.last_ms = e.last_ms.max(a.ts_ms);
            return false;
        }
        self.next_id += 1;
        self.entries.push(Entry {
            id: self.next_id,
            app: a.app,
            remote: a.remote,
            attempts: 1,
            first_ms: a.ts_ms,
            last_ms: a.ts_ms,
            state: PromptState::Waiting,
            opened_ms: None,
        });
        true
    }

    /// Shows waiting prompts while the rate allows, and turns open prompts
    /// left unanswered for a minute into pending ones. Returns whether
    /// anything changed.
    pub fn tick(&mut self, now_ms: i64) -> bool {
        let mut changed = false;
        while self.shown.front().is_some_and(|&t| now_ms - t >= MINUTE_MS) {
            self.shown.pop_front();
        }
        for e in &mut self.entries {
            if e.state == PromptState::Open
                && e.opened_ms.is_some_and(|t| now_ms - t >= OPEN_FOR_MS)
            {
                e.state = PromptState::Pending;
                changed = true;
            }
        }
        for e in &mut self.entries {
            if self.shown.len() >= SHOWN_PER_MINUTE {
                break;
            }
            if e.state == PromptState::Waiting {
                e.state = PromptState::Open;
                e.opened_ms = Some(now_ms);
                self.shown.push_back(now_ms);
                changed = true;
            }
        }
        changed
    }

    pub fn get(&self, id: u64) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Removes a prompt that was answered.
    pub fn remove(&mut self, id: u64) -> Option<Entry> {
        let i = self.entries.iter().position(|e| e.id == id)?;
        Some(self.entries.remove(i))
    }

    /// "Decide later": the prompt stays, pending, and the app stays blocked.
    pub fn later(&mut self, id: u64) -> bool {
        match self.entries.iter_mut().find(|e| e.id == id) {
            Some(e) if e.state != PromptState::Pending => {
                e.state = PromptState::Pending;
                true
            }
            _ => false,
        }
    }

    /// The app has a rule now (from a prompt, a switch or the CLI).
    pub fn forget_app(&mut self, app: AppId) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.app != app);
        self.entries.len() != before
    }

    pub fn clear(&mut self) -> bool {
        let had = !self.entries.is_empty();
        self.entries.clear();
        had
    }

    /// Open first, then waiting, then pending; oldest first within each.
    pub fn list(&self) -> Vec<Entry> {
        let rank = |s: PromptState| match s {
            PromptState::Open => 0,
            PromptState::Waiting => 1,
            PromptState::Pending => 2,
        };
        let mut list = self.entries.clone();
        list.sort_by_key(|e| (rank(e.state), e.first_ms, e.id));
        list
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Blocked attempts in, prompts and automatic allows out.
pub struct Prompter {
    queue: Mutex<Queue>,
    monitor: Arc<Mutex<Monitor>>,
    store: Arc<Mutex<Store>>,
    enforcer: Arc<Enforcer>,
    notes: broadcast::Sender<Notification>,
    abused: Vec<String>,
    attempts: mpsc::UnboundedSender<Attempt>,
}

impl Prompter {
    /// The prompter, and where its attempts arrive (for [`Prompter::run`]).
    pub fn new(
        monitor: Arc<Mutex<Monitor>>,
        store: Arc<Mutex<Store>>,
        enforcer: Arc<Enforcer>,
        notes: broadcast::Sender<Notification>,
    ) -> (Arc<Prompter>, mpsc::UnboundedReceiver<Attempt>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let p = Arc::new(Prompter {
            queue: Mutex::new(Queue::default()),
            monitor,
            store,
            enforcer,
            notes,
            abused: abused_tools(),
            attempts: tx,
        });
        (p, rx)
    }

    /// From the WFP drop thread: must return at once.
    pub fn offer(&self, attempt: Attempt) {
        let _ = self.attempts.send(attempt);
    }

    pub async fn run(
        self: Arc<Self>,
        mut attempts: mpsc::UnboundedReceiver<Attempt>,
        shutdown: CancellationToken,
    ) {
        let mut tick = tokio::time::interval(TICK);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                Some(a) = attempts.recv() => {
                    let this = Arc::clone(&self);
                    // Reading a file's signature can take a moment.
                    let _ = tokio::task::spawn_blocking(move || this.handle(a)).await;
                }
                _ = tick.tick() => {
                    if lock(&self.queue).tick(now_unix_ms()) {
                        self.publish();
                    }
                }
            }
        }
    }

    fn handle(&self, a: Attempt) {
        let mode = lock(&self.store).firewall_mode().unwrap_or_default();
        if mode != Mode::AskToConnect {
            return;
        }
        let Some(record) = lock(&self.monitor).app_record(a.app) else {
            return;
        };
        if target_of(&record).is_none() || self.enforcer.is_protected(&record.path) {
            return;
        }
        // Already decided for the whole app (the rule may still be on its way).
        let decided = lock(&self.store).rules().is_ok_and(|rules| {
            rules
                .iter()
                .any(|r| r.app == a.app && r.direction == Direction::Out && r.scope == Scope::Any)
        });
        if decided {
            return;
        }
        let path_class = record
            .path
            .contains('\\')
            .then(|| w4_sys::trust::path_class(&record.path));
        // A new app's signature may not have been read yet.
        let trust = if record.trust.signature.is_none() && record.path.contains('\\') {
            w4_sys::trust::read(&record.path)
        } else {
            record.trust.clone()
        };
        if allowed_without_asking(&record.path, path_class, &trust, &self.abused) {
            self.allow_without_asking(a.app, &record.path);
            return;
        }
        if lock(&self.queue).attempt(a) {
            tracing::info!(app = %record.path, remote = %a.remote, "Ask to Connect: prompt");
        }
    }

    fn allow_without_asking(&self, app: AppId, path: &str) {
        let rule = NewRule {
            app,
            direction: Direction::Out,
            action: Action::Allow,
            scope: Scope::Any,
            origin: Origin::Baseline,
            note: Some("Allowed without asking: a Microsoft-signed system program".into()),
            expires: None,
        };
        match lock(&self.store).set_rule(&rule, now_unix_ms(), "win4tress (Ask to Connect)") {
            Ok(r) => {
                tracing::info!(rule = r.id, app = %path, "Ask to Connect: allowed without asking");
                self.enforcer.changed();
            }
            Err(e) => tracing::warn!(app = %path, "Ask to Connect: allowing failed: {e}"),
        }
    }

    /// Answers a prompt. Allow and Block set a rule for the app's outgoing
    /// connections, to everything or just the prompt's host.
    /// The app a prompt is about, if it's still there.
    pub fn app_of(&self, id: u64) -> Option<AppId> {
        lock(&self.queue).get(id).map(|e| e.app)
    }

    /// Answers a prompt; `expires` makes a whole-app decision temporary.
    pub fn decide(
        &self,
        id: u64,
        decision: Decision,
        scope: DecisionScope,
        expires: Option<Expiry>,
        who: &str,
    ) -> Result<Option<RuleId>, String> {
        let entry = lock(&self.queue)
            .get(id)
            .cloned()
            .ok_or_else(|| format!("no prompt {id}: it was answered or has gone"))?;
        let action = match decision {
            Decision::Later => {
                if lock(&self.queue).later(id) {
                    self.publish();
                }
                return Ok(None);
            }
            Decision::Allow => Action::Allow,
            Decision::Block => Action::Block,
        };
        let scope = match scope {
            DecisionScope::App => Scope::Any,
            DecisionScope::Host => {
                let ip = entry.remote.ip();
                let name = lock(&self.monitor).remote(entry.app, ip).0.name;
                Scope::Hosts {
                    hosts: vec![name.unwrap_or_else(|| ip.to_string())],
                }
            }
        };
        let whole_app = scope == Scope::Any;
        let rule = NewRule {
            app: entry.app,
            direction: Direction::Out,
            action,
            scope,
            origin: Origin::Prompt,
            note: None,
            expires: expires.filter(|_| whole_app),
        };
        let r = lock(&self.store)
            .set_rule(&rule, now_unix_ms(), who)
            .map_err(|e| format!("saving the rule: {e}"))?;
        tracing::info!(
            rule = r.id,
            app = entry.app,
            ?decision,
            by = who,
            "prompt answered"
        );
        self.enforcer.changed();
        {
            let mut q = lock(&self.queue);
            if whole_app {
                q.forget_app(entry.app);
            } else {
                q.remove(id);
            }
        }
        self.publish();
        Ok(Some(r.id))
    }

    /// An app got an outgoing rule some other way.
    pub fn forget_app(&self, app: AppId) {
        if lock(&self.queue).forget_app(app) {
            self.publish();
        }
    }

    /// The mode left Ask to Connect.
    pub fn clear(&self) {
        if lock(&self.queue).clear() {
            self.publish();
        }
    }

    pub fn list(&self) -> PromptsResult {
        let entries = lock(&self.queue).list();
        let monitor = lock(&self.monitor);
        let prompts = entries
            .into_iter()
            .map(|e| {
                let record = monitor.app_record(e.app);
                let (remote, owner) = monitor.remote(e.app, e.remote.ip());
                Prompt {
                    id: e.id,
                    app: monitor.app_ref(e.app),
                    company: record.as_ref().and_then(|r| r.company.clone()),
                    trust: record.as_ref().map(|r| r.trust.clone()).unwrap_or_default(),
                    path_class: record
                        .as_ref()
                        .filter(|r| r.path.contains('\\'))
                        .map(|r| w4_sys::trust::path_class(&r.path)),
                    first_seen_ms: record.as_ref().map_or(e.first_ms, |r| r.first_seen_ms),
                    remote,
                    port: e.remote.port(),
                    owner,
                    attempts: e.attempts,
                    first_ms: e.first_ms,
                    last_ms: e.last_ms,
                    state: e.state,
                }
            })
            .collect();
        PromptsResult { prompts }
    }

    fn publish(&self) {
        let params = serde_json::to_value(self.list()).unwrap_or_default();
        let _ = self
            .notes
            .send(Notification::new(notification::PROMPTS, params));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_792_886_400_000;

    fn attempt(app: AppId, ts_ms: i64) -> Attempt {
        Attempt {
            app,
            remote: "203.0.113.7:443".parse().unwrap(),
            ts_ms,
        }
    }

    fn states(q: &Queue) -> Vec<(AppId, PromptState)> {
        q.list().iter().map(|e| (e.app, e.state)).collect()
    }

    #[test]
    fn one_prompt_per_app() {
        let mut q = Queue::default();
        assert!(q.attempt(attempt(1, T0)));
        assert!(!q.attempt(attempt(1, T0 + 5)));
        let e = &q.list()[0];
        assert_eq!((e.attempts, e.first_ms, e.last_ms), (2, T0, T0 + 5));
        assert_eq!(e.state, PromptState::Waiting, "shown on the next tick");
        assert!(q.tick(T0 + 10));
        assert_eq!(states(&q), [(1, PromptState::Open)]);
    }

    #[test]
    fn five_shown_a_minute_and_the_rest_wait() {
        let mut q = Queue::default();
        for app in 1..=7 {
            q.attempt(attempt(app, T0));
        }
        q.tick(T0);
        let open = |q: &Queue| {
            q.list()
                .iter()
                .filter(|e| e.state == PromptState::Open)
                .count()
        };
        assert_eq!(open(&q), 5);
        // Answering doesn't free a slot within the minute.
        let first = q.list()[0].id;
        q.remove(first);
        q.tick(T0 + 30_000);
        assert_eq!(open(&q), 4);
        // A minute on: the open ones are pending and the rest are shown.
        q.tick(T0 + MINUTE_MS);
        assert_eq!(open(&q), 2);
        assert_eq!(
            q.list()
                .iter()
                .filter(|e| e.state == PromptState::Pending)
                .count(),
            4
        );
    }

    #[test]
    fn later_forget_and_clear() {
        let mut q = Queue::default();
        q.attempt(attempt(1, T0));
        q.attempt(attempt(2, T0 + 1));
        q.tick(T0);
        let id = q.list()[0].id;
        assert!(q.later(id));
        assert!(!q.later(id), "already pending");
        assert_eq!(
            states(&q),
            [(2, PromptState::Open), (1, PromptState::Pending)]
        );
        // A pending app's next attempts don't prompt again.
        assert!(!q.attempt(attempt(1, T0 + 2)));
        assert!(q.forget_app(2));
        assert!(!q.forget_app(2));
        assert!(q.clear());
        assert!(q.list().is_empty());
    }
}
