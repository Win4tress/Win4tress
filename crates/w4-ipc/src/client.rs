//! Pipe client used by the CLI and the UI.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};
use tokio_util::sync::CancellationToken;

use crate::api::{HelloParams, HelloResult, SubscribeParams, method};
use crate::rpc::{self, Incoming, Notification, Request, Response, RpcError};
use crate::{MAX_MESSAGE, PROTOCOL_VERSION};

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PIPE_BUSY: i32 = 231;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("the win4tress service is not running")]
    NotRunning,
    #[error("the connection to the win4tress service was lost")]
    Disconnected,
    #[error("service error: {0}")]
    Rpc(#[from] RpcError),
    #[error("unexpected data from the service: {0}")]
    Decode(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Response>>>>;

pub struct Client {
    out: mpsc::Sender<String>,
    pending: Pending,
    next_id: AtomicU64,
    notifications: Mutex<Option<mpsc::Receiver<Notification>>>,
    closed: CancellationToken,
}

impl Client {
    pub async fn connect(pipe_name: &str) -> Result<Client, ClientError> {
        let pipe = open(pipe_name).await?;
        let (read, write) = tokio::io::split(pipe);
        let (out_tx, mut out_rx) = mpsc::channel::<String>(64);
        let (note_tx, note_rx) = mpsc::channel::<Notification>(256);
        let pending: Pending = Arc::default();
        let closed = CancellationToken::new();

        let writer_closed = closed.clone();
        tokio::spawn(async move {
            let mut sink = FramedWrite::new(write, LinesCodec::new_with_max_length(MAX_MESSAGE));
            loop {
                tokio::select! {
                    _ = writer_closed.cancelled() => break,
                    message = out_rx.recv() => {
                        let Some(message) = message else { break };
                        if sink.send(message).await.is_err() {
                            break;
                        }
                    }
                }
            }
            writer_closed.cancel();
        });

        let reader_pending = Arc::clone(&pending);
        let reader_closed = closed.clone();
        tokio::spawn(async move {
            let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_MESSAGE));
            loop {
                let line = tokio::select! {
                    // Closed or dropped: stop reading, so the pipe closes and
                    // the server's end of the connection ends too.
                    _ = reader_closed.cancelled() => break,
                    line = lines.next() => line,
                };
                let Some(Ok(line)) = line else { break };
                match serde_json::from_str::<Incoming>(&line) {
                    Ok(Incoming::Response(response)) => {
                        let waiter = reader_pending
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&response.id);
                        if let Some(waiter) = waiter {
                            let _ = waiter.send(response);
                        }
                    }
                    // Drop notifications rather than stall responses if the consumer is slow.
                    Ok(Incoming::Notification(note)) => {
                        let _ = note_tx.try_send(note);
                    }
                    Err(e) => tracing::debug!("ignoring malformed message from service: {e}"),
                }
            }
            reader_closed.cancel();
            reader_pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clear();
        });

        Ok(Client {
            out: out_tx,
            pending,
            next_id: AtomicU64::new(1),
            notifications: Mutex::new(Some(note_rx)),
            closed,
        })
    }

    pub async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, ClientError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = Request {
            jsonrpc: rpc::VERSION.into(),
            id,
            method: method.into(),
            params: serde_json::to_value(params)?,
        };
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, tx);

        let response = async {
            self.out
                .send(serde_json::to_string(&request)?)
                .await
                .map_err(|_| ClientError::Disconnected)?;
            rx.await.map_err(|_| ClientError::Disconnected)
        };
        let response = tokio::select! {
            r = response => r,
            _ = self.closed.cancelled() => Err(ClientError::Disconnected),
        };
        let response = match response {
            Ok(r) => r,
            Err(e) => {
                self.pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&id);
                return Err(e);
            }
        };

        if let Some(error) = response.error {
            return Err(error.into());
        }
        Ok(serde_json::from_value(
            response.result.unwrap_or(Value::Null),
        )?)
    }

    /// Handshake; fails if the service speaks a different protocol version.
    pub async fn hello(&self, client: &str) -> Result<HelloResult, ClientError> {
        let params = HelloParams {
            protocol: PROTOCOL_VERSION,
            client: client.into(),
        };
        let hello: HelloResult = self.call(method::HELLO, params).await?;
        if hello.protocol != PROTOCOL_VERSION {
            return Err(RpcError::new(
                RpcError::PROTOCOL_MISMATCH,
                format!(
                    "service speaks protocol {}, this client {}; update win4tress",
                    hello.protocol, PROTOCOL_VERSION
                ),
            )
            .into());
        }
        Ok(hello)
    }

    /// Starts the notification stream. Can be taken once per connection.
    pub async fn subscribe(
        &self,
        topics: &[&str],
    ) -> Result<mpsc::Receiver<Notification>, ClientError> {
        let params = SubscribeParams {
            topics: topics.iter().map(|t| t.to_string()).collect(),
        };
        let _: Value = self.call(method::SUBSCRIBE, params).await?;
        self.notifications
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or_else(|| io::Error::other("already subscribed").into())
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    pub async fn closed(&self) {
        self.closed.cancelled().await
    }
}

impl Drop for Client {
    /// Ends the connection. Otherwise the reader would keep the pipe open and
    /// the server waiting for good: one leaked connection, on both ends, per
    /// client (the service polling the resolver every 2 s leaked ~30 a minute).
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

async fn open(pipe_name: &str) -> Result<NamedPipeClient, ClientError> {
    // All instances can be briefly busy while the server creates the next one.
    for _ in 0..40 {
        match ClientOptions::new().open(pipe_name) {
            Ok(pipe) => return Ok(pipe),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                return Err(ClientError::NotRunning);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(io::Error::other("the win4tress service is busy").into())
}
