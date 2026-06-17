//! [`PunchedSocket`]: the output of a successful traversal (Phase 3).
//!
//! After hole punching succeeds, this wraps the single UDP socket whose remote
//! peer is the other side. The same socket carried STUN and punch traffic and
//! will carry the QUIC carrier next (Phase 4), so the local port is reused
//! throughout — which is exactly what NAT traversal requires.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::Result;
use crate::punch::{self, NONCE_LEN, OBFS_LEN};

/// A UDP socket whose remote peer was established by hole punching.
#[derive(Debug)]
pub struct PunchedSocket {
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
}

impl PunchedSocket {
    /// Run the punch loop on `socket` toward `peers` and, on success, wrap the
    /// socket with its confirmed peer.
    pub async fn connect(
        socket: UdpSocket,
        peers: &[SocketAddr],
        nonce: &[u8; NONCE_LEN],
        obfs: &[u8; OBFS_LEN],
        deadline: Duration,
    ) -> Result<Self> {
        let peer = punch::punch(&socket, peers, nonce, obfs, deadline).await?;
        let local = socket.local_addr()?;
        Ok(Self { socket, peer, local })
    }

    /// The confirmed remote peer address.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The local address the socket is bound to.
    pub fn local(&self) -> SocketAddr {
        self.local
    }

    /// Borrow the underlying socket (e.g. to drive a QUIC endpoint over it).
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    /// Send a datagram to the confirmed peer.
    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        Ok(self.socket.send_to(buf, self.peer).await?)
    }

    /// Receive a datagram, returning the number of bytes and the source.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok(self.socket.recv_from(buf).await?)
    }

    /// Consume the wrapper, yielding the raw socket and the confirmed peer.
    pub fn into_parts(self) -> (UdpSocket, SocketAddr) {
        (self.socket, self.peer)
    }
}
