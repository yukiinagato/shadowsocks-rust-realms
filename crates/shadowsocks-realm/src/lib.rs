//! # shadowsocks-realm
//!
//! Protocol-agnostic **P2P UDP NAT-traversal** building blocks, compatible with
//! the open-source [Hysteria Realms] rendezvous server (`hysteria-realm-server`).
//!
//! This crate intentionally has **no** shadowsocks dependencies. It provides the
//! three reusable pieces of "Realms":
//!
//! 1. [`rendezvous`] — a tiny HTTP/SSE client that introduces two peers.
//! 2. [`stun`] — RFC 5389 Binding discovery of a socket's reflexive address.
//! 3. [`punch`] — the byte-exact `HYRLMv1` Hello/Ack codec and punch loop.
//!
//! Plus the supporting infrastructure used by the shadowsocks integration:
//!
//! * [`socket`] — a [`socket::PunchedSocket`]: a single connected UDP socket
//!   whose remote peer is the other side, with STUN/punch/QUIC demultiplexing.
//! * [`portmap`] — best-effort UPnP-IGD / NAT-PMP TCP port mapping (PATH B).
//! * [`url`] — `realm://token@host/realm-name` URL parsing.
//!
//! The output of a successful traversal is a [`socket::PunchedSocket`]; what runs
//! on top (QUIC carrier, shadowsocks AEAD) lives in the `shadowsocks` crate.
//!
//! [Hysteria Realms]: https://v2.hysteria.network/docs/advanced/Realms/
#![forbid(unsafe_code)]

pub mod control;
pub mod error;
pub mod path_manager;
pub mod portmap;
pub mod punch;
pub mod quic;
pub mod rendezvous;
pub mod session;
pub mod socket;
pub mod stun;
pub mod tls;
pub mod url;

pub use error::{Error, Result};
pub use url::RealmUrl;

/// The `HYRLMv1` punch protocol magic, matching `apernet/hysteria`
/// (`extras/realm/punch.go`): the 8 bytes `"HYRLMv1\0"`.
pub const HYRLM_MAGIC: [u8; 8] = *b"HYRLMv1\0";

/// A fresh punch session: random nonce (16B) and obfuscation key (32B), with
/// their hex encodings for the rendezvous JSON (32 / 64 hex chars).
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// Punch nonce bytes.
    pub nonce: [u8; 16],
    /// Obfuscation key bytes.
    pub obfs: [u8; 32],
    /// Hex-encoded nonce (32 chars).
    pub nonce_hex: String,
    /// Hex-encoded obfuscation key (64 chars).
    pub obfs_hex: String,
}

/// Generate a random 32-byte session-binding token for the direct-TCP path
/// (PATH B): the server offers it over the control stream and the client
/// presents it (under ss AEAD) when dialing the mapped TCP endpoint.
pub fn random_token() -> [u8; 32] {
    use rand::RngExt;
    let mut token = [0u8; 32];
    rand::rng().fill(&mut token[..]);
    token
}

/// Generate a fresh [`SessionKeys`] for a connect/punch attempt.
pub fn random_session() -> SessionKeys {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut nonce = [0u8; 16];
    let mut obfs = [0u8; 32];
    rng.fill(&mut nonce[..]);
    rng.fill(&mut obfs[..]);
    SessionKeys {
        nonce_hex: hex::encode(nonce),
        obfs_hex: hex::encode(obfs),
        nonce,
        obfs,
    }
}
