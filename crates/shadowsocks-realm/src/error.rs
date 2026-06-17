//! Crate-wide error and result types.

use std::io;

/// Convenience result type used throughout `shadowsocks-realm`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the NAT-traversal building blocks.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure (socket, timeout source, etc.).
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// A `realm://` URL could not be parsed.
    #[error("invalid realm url: {0}")]
    InvalidUrl(String),

    /// The rendezvous server returned an error or an unexpected response.
    #[error("rendezvous error: {0}")]
    Rendezvous(String),

    /// STUN discovery failed or returned a malformed response.
    #[error("stun error: {0}")]
    Stun(String),

    /// A received punch packet was malformed (bad magic, length, or nonce).
    #[error("punch protocol error: {0}")]
    Punch(String),

    /// Hole punching did not succeed before the deadline.
    #[error("hole punching timed out")]
    PunchTimeout,

    /// UPnP/NAT-PMP port mapping failed (PATH B is best-effort; callers may
    /// treat this as non-fatal and fall back to the QUIC path).
    #[error("port mapping error: {0}")]
    PortMap(String),
}
