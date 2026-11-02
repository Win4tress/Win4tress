//! JSON-RPC 2.0 envelopes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: &str = "2.0";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    pub fn new(id: u64, outcome: Result<Value, RpcError>) -> Self {
        let (result, error) = match outcome {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        };
        Response {
            jsonrpc: VERSION.into(),
            id,
            result,
            error,
        }
    }
}

/// Server-to-client message without an id.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl Notification {
    pub fn new(method: &str, params: Value) -> Self {
        Notification {
            jsonrpc: VERSION.into(),
            method: method.into(),
            params,
        }
    }
}

/// What a client can receive: a response (has `id`) or a notification.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Incoming {
    Response(Response),
    Notification(Notification),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message} (code {code})")]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub const PARSE: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL: i32 = -32603;
    /// The caller isn't allowed to do this (SPEC §4.3).
    pub const FORBIDDEN: i32 = -32003;
    pub const NOT_FOUND: i32 = -32004;
    /// A feature the service can't provide right now (e.g. history disabled).
    pub const UNAVAILABLE: i32 = -32005;
    /// "Require elevation" is on and the caller isn't elevated: the UI retries
    /// through its elevated helper (SPEC §4.3).
    pub const ELEVATION_REQUIRED: i32 = -32006;
    /// Block All would cut off the caller's Remote Desktop session; ask, then
    /// retry with `confirm_remote`.
    pub const REMOTE_SESSION: i32 = -32007;
    pub const PROTOCOL_MISMATCH: i32 = -32010;

    pub fn new(code: i32, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
        }
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(Self::METHOD_NOT_FOUND, format!("unknown method {method}"))
    }

    pub fn invalid_params(err: impl std::fmt::Display) -> Self {
        Self::new(Self::INVALID_PARAMS, format!("invalid params: {err}"))
    }

    pub fn not_found(what: impl Into<String>) -> Self {
        Self::new(Self::NOT_FOUND, what)
    }

    pub fn forbidden(why: impl Into<String>) -> Self {
        Self::new(Self::FORBIDDEN, why)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn incoming_distinguishes_response_and_notification() {
        let r: Incoming =
            serde_json::from_value(json!({"jsonrpc":"2.0","id":7,"result":{}})).unwrap();
        assert!(matches!(r, Incoming::Response(Response { id: 7, .. })));
        let n: Incoming =
            serde_json::from_value(json!({"jsonrpc":"2.0","method":"x","params":[1]})).unwrap();
        assert!(matches!(n, Incoming::Notification(Notification { .. })));
    }

    #[test]
    fn error_response_omits_result() {
        let r = Response::new(1, Err(RpcError::method_not_found("nope")));
        let v = serde_json::to_value(r).unwrap();
        assert!(v.get("result").is_none());
        assert_eq!(v["error"]["code"], RpcError::METHOD_NOT_FOUND);
    }
}
