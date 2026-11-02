//! The resolver's pipe, for the service: status and the recent lookups.

use std::sync::Arc;

use serde_json::Value;
use w4_dns::config::Upstream;
use w4_dns::status::{LogParams, LogResult, ResolverStatus, method};
use w4_ipc::{Caller, Handler, RpcError};

use crate::resolve::{Resolver, now_ms};

pub struct Api {
    pub resolver: Arc<Resolver>,
    pub started_ms: i64,
    pub listening: Vec<String>,
}

impl Api {
    fn status(&self) -> ResolverStatus {
        let r = &self.resolver;
        let s = r.current.get();
        let observing = match s.config.observe {
            w4_dns::config::Observe::On => true,
            w4_dns::config::Observe::Off => false,
            w4_dns::config::Observe::Auto => r.upstream_blocks() == Some(true),
        };
        ResolverStatus {
            version: env!("CARGO_PKG_VERSION").into(),
            started_ms: self.started_ms,
            listening: self.listening.clone(),
            filtering: s.config.filtering,
            observing,
            paused_until_ms: s.config.paused_until_ms.filter(|t| *t > now_ms()),
            passthrough: s.config.passthrough,
            upstream: match &s.config.upstream {
                Upstream::System => "system".into(),
                Upstream::Doh { .. } => s.doh_host.clone().unwrap_or_default(),
            },
            system_servers: s
                .config
                .system_servers
                .iter()
                .map(ToString::to_string)
                .collect(),
            blocklist_domains: s.blocklist.as_ref().map_or(0, |b| b.len()),
            regex_rules: s.rules.regex_count(),
            upstream_blocks: r.upstream_blocks(),
            cache_entries: r.cache.len(),
            problems: r
                .current
                .error()
                .map(|e| format!("config.json not loaded: {e}"))
                .into_iter()
                .chain(s.problems.iter().cloned())
                .collect(),
            counters: r.journal.counters(),
            top_blocked: r.journal.top_blocked(20),
        }
    }
}

impl Handler for Api {
    fn handle(&self, _caller: &Caller, method: &str, params: Value) -> Result<Value, RpcError> {
        let to_value = |v: &dyn erased::Ser| v.json();
        match method {
            "hello" => Ok(
                serde_json::json!({ "protocol": w4_ipc::PROTOCOL_VERSION, "server_version": env!("CARGO_PKG_VERSION") }),
            ),
            method::STATUS => to_value(&self.status()),
            method::LOG => {
                let p: LogParams = serde_json::from_value(params).unwrap_or_default();
                let entries = self
                    .resolver
                    .journal
                    .since(p.after, p.limit.unwrap_or(500).min(5_000));
                to_value(&LogResult { entries })
            }
            other => Err(RpcError::method_not_found(other)),
        }
    }
}

/// Serializing behind a trait object, so `handle` can call one helper.
mod erased {
    use serde_json::Value;
    use w4_ipc::RpcError;

    pub trait Ser {
        fn json(&self) -> Result<Value, RpcError>;
    }

    impl<T: serde::Serialize> Ser for T {
        fn json(&self) -> Result<Value, RpcError> {
            serde_json::to_value(self).map_err(|e| RpcError::new(RpcError::INTERNAL, e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::Value;
    use tokio::sync::broadcast;
    use tokio_util::sync::CancellationToken;
    use w4_ipc::{Caller, Client, ClientError, Handler, RpcError, ServerConfig};

    #[test]
    fn the_pipe_s_access_list_parses() {
        w4_ipc::security::PipeSecurity::from_sddl(w4_dns::status::PIPE_SDDL).unwrap();
    }

    struct Echo;

    impl Handler for Echo {
        fn handle(&self, _: &Caller, _: &str, params: Value) -> Result<Value, RpcError> {
            Ok(params)
        }
    }

    /// The running account's SID, e.g. `S-1-5-21-…-1001`.
    fn my_sid() -> String {
        let out = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        let line = String::from_utf8_lossy(&out.stdout);
        line.trim()
            .rsplit(',')
            .next()
            .unwrap()
            .trim_matches('"')
            .to_string()
    }

    async fn connect(name: &str) -> Client {
        for _ in 0..100 {
            match Client::connect(name).await {
                Ok(client) => return client,
                Err(ClientError::NotRunning) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(e) => panic!("connecting: {e}"),
            }
        }
        panic!("the pipe never came back");
    }

    /// The pipe's access list as the resolver, installed, meets it: it runs as
    /// LocalService, neither SYSTEM nor an administrator, so only the
    /// LocalService entry applies. The test's account stands in.
    fn as_the_resolver() -> String {
        let sid = my_sid();
        assert!(sid.starts_with("S-1-"), "no SID from whoami: {sid:?}");
        let sddl = w4_dns::status::PIPE_SDDL
            .replace("(A;;GA;;;BA)", "")
            .replace(";LS)", &format!(";{sid})"));
        assert!(
            sddl.contains(&sid),
            "the LocalService entry wasn't found in {sddl}"
        );
        sddl
    }

    /// After each client the resolver opens the next instance of its pipe,
    /// which takes read and write access as well as "create instance". With
    /// "create instance" alone, the second instance failed and the pipe was
    /// gone after the service's first poll.
    #[tokio::test]
    async fn the_resolver_s_account_can_open_the_next_instance() {
        use tokio::net::windows::named_pipe::ServerOptions;

        let security = w4_ipc::security::PipeSecurity::from_sddl(&as_the_resolver()).unwrap();
        let name = format!(r"\\.\pipe\win4tress-dns-next-{}", std::process::id());
        let open = |first: bool| {
            // SAFETY: `security` outlives the call and points to a valid SECURITY_ATTRIBUTES.
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first)
                    .create_with_security_attributes_raw(&name, security.as_ptr())
            }
        };
        let _first = open(true).unwrap();
        let _second = open(false).expect("the next instance");
    }

    /// Client after client, end to end, with the resolver's rights (the client
    /// here is the same account; the service's is SYSTEM).
    #[tokio::test(flavor = "multi_thread")]
    async fn the_resolver_s_account_keeps_its_pipe_open() {
        let sddl = as_the_resolver();
        let name = format!(r"\\.\pipe\win4tress-dns-test-{}", std::process::id());
        let (notes, _) = broadcast::channel(4);
        let shutdown = CancellationToken::new();
        let config = ServerConfig {
            pipe_name: name.clone(),
            sddl,
        };
        let server = tokio::spawn(w4_ipc::server::serve(
            config,
            Arc::new(Echo),
            notes,
            shutdown.clone(),
        ));
        for i in 0..3 {
            let client = connect(&name).await;
            let echoed: Value = client.call("echo", i).await.unwrap();
            assert_eq!(echoed, i, "client {i}");
        }
        shutdown.cancel();
        server.await.unwrap().unwrap();
    }
}
