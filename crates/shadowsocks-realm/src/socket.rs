//! [`PunchedSocket`]: the output of a successful traversal (Phase 3).
//!
//! After hole punching succeeds, this wraps the single UDP socket whose remote
//! peer is the other side. The same socket carried STUN and punch traffic and
//! will carry the QUIC carrier next (Phase 4), so the local port is reused
//! throughout — which is exactly what NAT traversal requires.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::Result;
use crate::punch::{self, NONCE_LEN, OBFS_LEN};

/// Bind a UDP socket for realm use.
///
/// Prefers an **IPv6 dual-stack** socket (`[::]`, with `IPV6_V6ONLY=false`) so
/// the one socket can reach BOTH IPv4 and IPv6 peers and STUN servers — crucial
/// on IPv6-preferred or NAT64/DNS64 networks (common on mobile and some macOS
/// setups), where a STUN hostname may resolve only to AAAA and a plain IPv4
/// (`0.0.0.0`) socket cannot reach it, making STUN fail instantly. Falls back to
/// IPv4 (`0.0.0.0`) if a dual-stack socket cannot be created (e.g. IPv6 disabled).
///
/// IPv4 destinations are sent from a dual-stack socket via their IPv4-mapped
/// IPv6 form — see [`map_to_socket_family`].
pub fn bind_realm_socket(port: u16) -> io::Result<UdpSocket> {
    match bind_dual_stack(port) {
        Ok(sock) => {
            log::debug!("realm: bound dual-stack (IPv4+IPv6) UDP socket on [::]:{port}");
            Ok(sock)
        }
        Err(e) => {
            log::debug!(
                "realm: dual-stack bind failed ({e}); falling back to IPv4 socket on 0.0.0.0:{port}"
            );
            let std_sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))?;
            std_sock.set_nonblocking(true)?;
            UdpSocket::from_std(std_sock)
        }
    }
}

fn bind_dual_stack(port: u16) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // Accept both IPv6 and IPv4-mapped traffic on this one socket.
    sock.set_only_v6(false)?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

/// Map a destination address to the socket's family for `send_to`.
///
/// A dual-stack IPv6 socket must address IPv4 destinations through their
/// IPv4-mapped IPv6 form (`::ffff:a.b.c.d`); sending a raw `V4` address from a
/// `V6` socket fails. An IPv4 socket (or an already-IPv6 destination) is returned
/// unchanged. The transform is idempotent.
pub fn map_to_socket_family(socket: &UdpSocket, addr: SocketAddr) -> SocketAddr {
    let local_is_v6 = socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    match (local_is_v6, addr) {
        (true, SocketAddr::V4(v4)) => {
            SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
        }
        _ => addr,
    }
}

/// True if `socket` is a dual-stack IPv6 socket (and so can reach both families).
pub fn is_dual_stack(socket: &UdpSocket) -> bool {
    socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false)
}

/// Normalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) back to plain IPv4,
/// for display, exchange over the rendezvous, or parsing. Other addresses pass
/// through unchanged.
pub fn unmap(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr
        && let Some(v4) = v6.ip().to_ipv4_mapped()
    {
        return SocketAddr::new(v4.into(), v6.port());
    }
    addr
}

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
