//! Per-new-connection path selection between QUIC (PATH A) and direct TCP
//! (PATH B) (Phase 6).
//!
//! The client keeps one [`PathManager`] per realm server. Each *new* proxied
//! connection asks [`PathManager::select`] for the best currently-available
//! path: QUIC until a direct-TCP endpoint has been offered, verified and
//! adopted; native TCP afterwards. In-flight QUIC streams are unaffected, so the
//! switch is seamless (true mid-flow migration is the optional Phase 10).

use std::net::SocketAddr;
use std::sync::Mutex;

use crate::control::TOKEN_LEN;

/// The transport a new connection should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Open a new bidi stream on the QUIC carrier.
    Quic,
    /// Dial the native shadowsocks-over-TCP endpoint at this address, presenting
    /// the session token in the handshake.
    Tcp(SocketAddr),
}

#[derive(Debug, Clone, Copy)]
struct TcpPath {
    addr: SocketAddr,
    token: [u8; TOKEN_LEN],
}

/// Tracks the best available path for new connections to one realm server.
#[derive(Debug)]
pub struct PathManager {
    tcp: Mutex<Option<TcpPath>>,
    prefer_tcp: bool,
}

impl PathManager {
    /// Create a manager. `prefer_tcp` reflects the client's `prefer_tcp` config:
    /// when `false`, offered TCP endpoints are tracked but never selected.
    pub fn new(prefer_tcp: bool) -> Self {
        Self {
            tcp: Mutex::new(None),
            prefer_tcp,
        }
    }

    /// Record an adopted direct-TCP endpoint (after the client has verified it).
    pub fn set_tcp(&self, addr: SocketAddr, token: [u8; TOKEN_LEN]) {
        *self.tcp.lock().unwrap() = Some(TcpPath { addr, token });
    }

    /// Demote back to QUIC (e.g. on `TcpPathDown` or a TCP dial failure).
    pub fn mark_tcp_down(&self) {
        *self.tcp.lock().unwrap() = None;
    }

    /// Whether a direct-TCP path is currently adopted.
    pub fn tcp_available(&self) -> bool {
        self.tcp.lock().unwrap().is_some()
    }

    /// The session-binding token for the current TCP path, if any.
    pub fn tcp_token(&self) -> Option<[u8; TOKEN_LEN]> {
        self.tcp.lock().unwrap().map(|t| t.token)
    }

    /// Choose the path for a *new* connection.
    pub fn select(&self) -> Path {
        if self.prefer_tcp
            && let Some(t) = *self.tcp.lock().unwrap()
        {
            return Path::Tcp(t.addr);
        }
        Path::Quic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_on_quic_then_upgrades_and_falls_back() {
        let pm = PathManager::new(true);
        assert_eq!(pm.select(), Path::Quic);
        assert!(!pm.tcp_available());

        let addr: SocketAddr = "203.0.113.7:9000".parse().unwrap();
        pm.set_tcp(addr, [9u8; TOKEN_LEN]);
        assert_eq!(pm.select(), Path::Tcp(addr));
        assert_eq!(pm.tcp_token(), Some([9u8; TOKEN_LEN]));

        pm.mark_tcp_down();
        assert_eq!(pm.select(), Path::Quic);
        assert_eq!(pm.tcp_token(), None);
    }

    #[test]
    fn prefer_tcp_false_stays_on_quic() {
        let pm = PathManager::new(false);
        pm.set_tcp("203.0.113.7:9000".parse().unwrap(), [1u8; TOKEN_LEN]);
        // tracked, but never selected
        assert!(pm.tcp_available());
        assert_eq!(pm.select(), Path::Quic);
    }
}
