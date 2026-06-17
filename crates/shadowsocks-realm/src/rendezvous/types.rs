//! Rendezvous wire types (Phase 1).
//!
//! These mirror the JSON bodies of the `hysteria-realm-server` HTTP API. Field
//! names are chosen to (de)serialize exactly as the Go server expects.

use serde::{Deserialize, Serialize};

/// Body of `POST /v1/{realm}` — the server registering its candidate addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Candidate reflexive/local addresses, as `ip:port` strings.
    pub addresses: Vec<String>,
}

/// Response to a successful registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Opaque session identifier used as the bearer for session-scoped calls.
    pub session_id: String,
    /// Time-to-live in seconds; the registration must be refreshed before this.
    pub ttl: u64,
}

/// Body of `POST /v1/{realm}/connect` (client) and the peer info returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectBody {
    /// Candidate addresses of the sender.
    pub addresses: Vec<String>,
    /// 16-byte punch nonce, hex-encoded (32 chars).
    pub nonce: String,
    /// 32-byte obfuscation key, hex-encoded (64 chars).
    pub obfs: String,
}
