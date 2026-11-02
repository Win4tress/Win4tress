//! IPC between the service and its clients (SPEC §4.2): JSON-RPC 2.0, one
//! message per line, over the named pipe `\\.\pipe\win4tress`.

pub mod api;
pub mod client;
pub mod rpc;
pub mod security;
pub mod server;
pub mod text;

pub use client::{Client, ClientError};
pub use rpc::{Notification, RpcError};
pub use security::CallerToken;
pub use server::{Caller, Handler, ServerConfig};

pub const PIPE_NAME: &str = r"\\.\pipe\win4tress";
pub const PROTOCOL_VERSION: u32 = 1;

/// SYSTEM and Administrators: full control. Interactive users: read/write, so the
/// unelevated UI and CLI can connect. Network logons are excluded (no `IU`), and
/// remote clients are rejected by the pipe itself.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Upper bound for one message, in bytes.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
