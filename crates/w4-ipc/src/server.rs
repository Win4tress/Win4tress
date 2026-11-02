//! Pipe server: one task per connection. Requests are answered in order;
//! notifications are forwarded once the client has called `subscribe`.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};
use tokio_util::sync::CancellationToken;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

use crate::api::method;
use crate::rpc::{self, Notification, Request, Response, RpcError};
use crate::security::{self, CallerToken, PipeSecurity};
use crate::{MAX_MESSAGE, PIPE_NAME, PIPE_SDDL};

/// Who sent a request (SPEC §4.3).
#[derive(Clone, Debug, Default)]
pub struct Caller {
    pub pid: Option<u32>,
    /// Read from the client's token on its first request; `None` if that failed.
    pub token: Option<CallerToken>,
}

impl Caller {
    /// May change rules, modes and settings: a member of Administrators,
    /// elevated or not.
    pub fn may_change(&self) -> bool {
        self.token.as_ref().is_some_and(|t| t.admin)
    }

    /// Running elevated: needed for `reset`.
    pub fn elevated(&self) -> bool {
        self.token.as_ref().is_some_and(|t| t.elevated)
    }

    /// For the audit log: user SID and process ID.
    pub fn describe(&self) -> String {
        format!(
            "{} (pid {})",
            self.token
                .as_ref()
                .map_or("unknown user", |t| t.user.as_str()),
            self.pid.map_or_else(|| "?".to_string(), |p| p.to_string())
        )
    }
}

/// Answers requests. Called on the connection's task, so it must be quick.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, caller: &Caller, method: &str, params: Value) -> Result<Value, RpcError>;
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub pipe_name: String,
    pub sddl: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            pipe_name: PIPE_NAME.into(),
            sddl: PIPE_SDDL.into(),
        }
    }
}

/// How long to wait before trying again to open the next pipe instance.
const RETRY_INSTANCE: Duration = Duration::from_secs(1);

/// Serves until `shutdown` is cancelled. Fails if the pipe name is already taken,
/// which also guards against another process squatting on it. After that, a
/// next instance that can't be opened is tried again every second rather than
/// ending the server: the pipe would be gone for good.
pub async fn serve(
    config: ServerConfig,
    handler: Arc<dyn Handler>,
    notifications: broadcast::Sender<Notification>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let security = PipeSecurity::from_sddl(&config.sddl)?;
    let create = |first: bool| -> io::Result<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true);
        // SAFETY: `security` outlives the call and points to a valid SECURITY_ATTRIBUTES.
        unsafe { options.create_with_security_attributes_raw(&config.pipe_name, security.as_ptr()) }
    };

    // The next instance, once one can be opened; `None` when shutting down.
    let next = || async {
        let mut warned = false;
        loop {
            match create(false) {
                Ok(server) => return Some(server),
                Err(e) if !warned => {
                    tracing::warn!(pipe = %config.pipe_name, "can't open the next pipe instance, trying again: {e}");
                    warned = true;
                }
                Err(_) => {}
            }
            tokio::select! {
                _ = shutdown.cancelled() => return None,
                _ = tokio::time::sleep(RETRY_INSTANCE) => {}
            }
        }
    };

    let mut server = create(true)?;
    tracing::info!(pipe = %config.pipe_name, "IPC server listening");
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = server.connect() => {
                if let Err(e) = result {
                    tracing::debug!("pipe connect failed: {e}");
                    let Some(again) = next().await else { return Ok(()) };
                    server = again;
                    continue;
                }
            }
        }
        // The client is served first, whatever happens to the next instance.
        let caller = Caller {
            pid: client_pid(&server),
            token: None,
        };
        tracing::debug!(pid = ?caller.pid, "client connected");
        tokio::spawn(connection(
            server,
            caller,
            Arc::clone(&handler),
            notifications.subscribe(),
            shutdown.clone(),
        ));
        let Some(again) = next().await else {
            return Ok(());
        };
        server = again;
    }
}

async fn connection(
    pipe: NamedPipeServer,
    mut caller: Caller,
    handler: Arc<dyn Handler>,
    mut notes: broadcast::Receiver<Notification>,
    shutdown: CancellationToken,
) {
    // Kept as an integer: the handle stays valid while the split halves live.
    let raw = pipe.as_raw_handle() as isize;
    let (read, write) = tokio::io::split(pipe);
    let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_MESSAGE));
    let mut out = FramedWrite::new(write, LinesCodec::new_with_max_length(MAX_MESSAGE));
    let mut subscribed = false;

    loop {
        let message = tokio::select! {
            _ = shutdown.cancelled() => break,
            line = lines.next() => match line {
                Some(Ok(line)) => {
                    // Impersonation needs data to have been read, so the first
                    // request is the earliest point. Synchronous: it must stay on
                    // this thread from impersonating to reverting.
                    if caller.token.is_none() {
                        match security::client_token(HANDLE(raw as *mut _)) {
                            Ok(token) => caller.token = Some(token),
                            Err(e) => tracing::warn!(pid = ?caller.pid, "couldn't read the client's token: {e}"),
                        }
                    }
                    Some(respond(&line, &caller, &*handler, &mut subscribed))
                }
                Some(Err(e)) => {
                    tracing::debug!(pid = ?caller.pid, "closing connection: {e}");
                    break;
                }
                None => break,
            },
            note = notes.recv(), if subscribed => match note {
                Ok(note) => serde_json::to_string(&note).ok(),
                Err(RecvError::Lagged(skipped)) => {
                    tracing::debug!(pid = ?caller.pid, skipped, "client lagging; notifications dropped");
                    None
                }
                Err(RecvError::Closed) => break,
            },
        };
        if let Some(message) = message
            && out.send(message).await.is_err()
        {
            break;
        }
    }
    tracing::debug!(pid = ?caller.pid, "client disconnected");
}

fn respond(line: &str, caller: &Caller, handler: &dyn Handler, subscribed: &mut bool) -> String {
    let response = match serde_json::from_str::<Request>(line) {
        Err(e) => Response::new(0, Err(RpcError::new(RpcError::PARSE, e.to_string()))),
        Ok(req) if req.jsonrpc != rpc::VERSION => Response::new(
            req.id,
            Err(RpcError::new(
                RpcError::INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            )),
        ),
        Ok(req) if req.method == method::SUBSCRIBE => {
            *subscribed = true;
            Response::new(req.id, Ok(json!({})))
        }
        Ok(req) => Response::new(req.id, handler.handle(caller, &req.method, req.params)),
    };
    serde_json::to_string(&response).expect("responses always serialize")
}

fn client_pid(pipe: &NamedPipeServer) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: the handle belongs to `pipe`, which outlives this call.
    unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }.ok()?;
    Some(pid)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    struct Echo;

    impl Handler for Echo {
        fn handle(&self, _: &Caller, method: &str, params: Value) -> Result<Value, RpcError> {
            match method {
                "fail" => Err(RpcError::new(RpcError::INTERNAL, "no")),
                _ => Ok(params),
            }
        }
    }

    fn check(out: &str) -> Value {
        let v: Value = serde_json::from_str(out).expect("response is JSON");
        assert_eq!(v["jsonrpc"], "2.0");
        assert_ne!(
            v.get("result").is_some(),
            v.get("error").is_some(),
            "exactly one of result/error: {out}"
        );
        v
    }

    proptest! {
        /// Whatever a client sends, it gets one well-formed response and no panic.
        #[test]
        fn any_line_gets_a_response(line in "\\PC{0,400}") {
            let mut subscribed = false;
            check(&respond(&line, &Caller::default(), &Echo, &mut subscribed));
        }

        #[test]
        fn requests_are_answered_with_their_id(
            id in any::<u64>(),
            method in "[a-z.]{0,16}",
            params in proptest::option::of(any::<i64>()),
        ) {
            let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
            let mut subscribed = false;
            let v = check(&respond(&line, &Caller::default(), &Echo, &mut subscribed));
            prop_assert_eq!(v["id"].as_u64(), Some(id));
            prop_assert_eq!(subscribed, method == "subscribe");
        }
    }
}
