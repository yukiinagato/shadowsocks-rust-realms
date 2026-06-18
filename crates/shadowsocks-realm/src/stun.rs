//! RFC 5389 STUN Binding discovery (Phase 2).
//!
//! Only the Binding transaction is implemented — enough to learn a UDP socket's
//! server-reflexive `ip:port` from one or more STUN servers, and to compare
//! results across servers to spot the port-prediction pattern of a symmetric
//! NAT. The codec is byte-compatible with `apernet/hysteria`'s `stun.go` and the
//! testbed oracle `testing/nat-sim/hyrlm.py`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::Rng;
use tokio::net::UdpSocket;

use crate::error::{Error, Result};

/// The 32-bit STUN magic cookie (RFC 5389 §6): `0x2112A442`.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Length of a STUN message header.
pub const HEADER_LEN: usize = 20;
/// Length of the STUN transaction ID.
pub const TXID_LEN: usize = 12;

/// The reflexive address learned for our socket from a single STUN server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunBinding {
    /// The STUN server queried.
    pub server: SocketAddr,
    /// Our public address as seen by that server (`XOR-MAPPED-ADDRESS`).
    pub reflexive: SocketAddr,
}

/// Build a Binding request message and return it together with its 12-byte
/// transaction ID (needed to validate and XOR-decode the response).
pub fn binding_request() -> ([u8; HEADER_LEN], [u8; TXID_LEN]) {
    let mut txid = [0u8; TXID_LEN];
    rand::rng().fill_bytes(&mut txid);

    let mut msg = [0u8; HEADER_LEN];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg[2..4].copy_from_slice(&0u16.to_be_bytes()); // attributes length = 0
    msg[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(&txid);
    (msg, txid)
}

/// Parse a Binding success response, returning the mapped (reflexive) address.
///
/// Validates message type, magic cookie and transaction ID, then prefers
/// `XOR-MAPPED-ADDRESS`, falling back to a plain `MAPPED-ADDRESS`.
pub fn parse_binding_response(pkt: &[u8], txid: &[u8; TXID_LEN]) -> Result<SocketAddr> {
    if pkt.len() < HEADER_LEN {
        return Err(Error::Stun("response shorter than header".into()));
    }
    let mtype = u16::from_be_bytes([pkt[0], pkt[1]]);
    let mlen = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);

    if mtype != BINDING_SUCCESS {
        return Err(Error::Stun(format!("not a binding success: {mtype:#06x}")));
    }
    if cookie != MAGIC_COOKIE {
        return Err(Error::Stun("bad magic cookie".into()));
    }
    if &pkt[8..20] != txid {
        return Err(Error::Stun("transaction id mismatch".into()));
    }

    let end = (HEADER_LEN + mlen).min(pkt.len());
    let mut off = HEADER_LEN;
    let mut fallback: Option<SocketAddr> = None;

    while off + 4 <= end {
        let atype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let alen = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) as usize;
        let vstart = off + 4;
        let vend = vstart + alen;
        if vend > end {
            break;
        }
        let val = &pkt[vstart..vend];
        match atype {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(sa) = parse_xor_mapped(val, txid) {
                    return Ok(sa);
                }
            }
            ATTR_MAPPED_ADDRESS if fallback.is_none() => {
                fallback = parse_mapped(val);
            }
            _ => {}
        }
        // attributes are padded to a 4-byte boundary
        off = vend + ((4 - (alen % 4)) % 4);
    }

    fallback.ok_or_else(|| Error::Stun("no address attribute in response".into()))
}

fn parse_xor_mapped(val: &[u8], txid: &[u8; TXID_LEN]) -> Option<SocketAddr> {
    if val.len() < 8 {
        return None;
    }
    let family = val[1];
    let xport = u16::from_be_bytes([val[2], val[3]]);
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    match family {
        0x01 => {
            let mut ip = [0u8; 4];
            for i in 0..4 {
                ip[i] = val[4 + i] ^ cookie[i];
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x02 if val.len() >= 20 => {
            let mut key = [0u8; 16];
            key[0..4].copy_from_slice(&cookie);
            key[4..16].copy_from_slice(txid);
            let mut ip = [0u8; 16];
            for i in 0..16 {
                ip[i] = val[4 + i] ^ key[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

fn parse_mapped(val: &[u8]) -> Option<SocketAddr> {
    if val.len() < 8 {
        return None;
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);
    match family {
        0x01 => {
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 if val.len() >= 20 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&val[4..20]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

/// Discover this socket's reflexive address from a single STUN server.
///
/// Sends up to `retries` Binding requests, each waiting `per_try` for a matching
/// response. Non-matching datagrams (other traffic on a shared socket) are
/// ignored within a try.
pub async fn discover(
    socket: &UdpSocket,
    server: SocketAddr,
    retries: usize,
    per_try: Duration,
) -> Result<SocketAddr> {
    let (req, txid) = binding_request();
    let mut buf = [0u8; 1500];
    // A dual-stack socket reaches IPv4 STUN servers via their IPv4-mapped form.
    let dst = crate::socket::map_to_socket_family(socket, server);

    for _ in 0..retries.max(1) {
        socket.send_to(&req, dst).await?;
        let deadline = tokio::time::Instant::now() + per_try;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, _from))) => {
                    if let Ok(sa) = parse_binding_response(&buf[..n], &txid) {
                        return Ok(sa);
                    }
                    // not our response; keep waiting until the deadline
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break, // timed out this try
            }
        }
    }
    Err(Error::Stun(format!("no STUN response from {server}")))
}

/// Which address families a socket can reach for STUN.
///
/// A dual-stack IPv6 socket can reach **both** families (IPv4 via IPv4-mapped
/// addressing); a plain IPv4 socket can reach only IPv4; a v6-only socket only
/// IPv6. Sending to a family the socket cannot reach fails instantly and looks
/// like "STUN blocked", so candidates must be filtered to reachable families.
fn reachable_families(socket: &UdpSocket) -> (bool, bool) {
    match socket.local_addr() {
        // We always create IPv6 sockets as dual-stack (see `bind_realm_socket`).
        Ok(a) if a.is_ipv6() => (true, true),
        _ => (true, false),
    }
}

/// Resolve a `host:port` string and discover the reflexive address from it,
/// trying each resolved address the socket can reach (dual-stack first tries the
/// family that resolves first, then the other) until one answers.
pub async fn discover_addr(socket: &UdpSocket, server: &str) -> Result<SocketAddr> {
    let (v4_ok, v6_ok) = reachable_families(socket);
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(server)
        .await
        .map_err(|e| Error::Stun(format!("resolving {server}: {e}")))?
        .filter(|a| if a.is_ipv4() { v4_ok } else { v6_ok })
        .collect();
    if resolved.is_empty() {
        return Err(Error::Stun(format!("no reachable address for {server}")));
    }
    let mut last = Error::Stun(format!("no STUN response from {server}"));
    for addr in resolved {
        match discover(socket, addr, 5, Duration::from_secs(1)).await {
            Ok(sa) => return Ok(sa),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Query STUN servers (by `host:port`) over the same socket, returning the
/// reflexive bindings. On a dual-stack socket this learns BOTH an IPv4 and an
/// IPv6 reflexive address (one per family) so the peer — whatever its own
/// stack — has a reachable candidate. The set of reflexive ports within a family
/// reveals NAT behaviour (identical ⇒ cone; differing ⇒ symmetric).
pub async fn discover_all(socket: &UdpSocket, servers: &[String]) -> Vec<StunBinding> {
    let (v4_ok, v6_ok) = reachable_families(socket);
    let mut out = Vec::new();
    let mut have_v4 = false;
    let mut have_v6 = false;
    for s in servers {
        // Once we hold a binding for every reachable family, stop (avoids
        // wasting a full timeout on an extra, redundant STUN server).
        if (have_v4 || !v4_ok) && (have_v6 || !v6_ok) {
            break;
        }
        let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(s).await {
            Ok(it) => it.collect(),
            Err(_) => continue,
        };
        for addr in resolved {
            let fam_ok = if addr.is_ipv4() { v4_ok } else { v6_ok };
            if !fam_ok {
                continue;
            }
            // Skip a family we already have a reflexive address for.
            if (addr.is_ipv4() && have_v4) || (addr.is_ipv6() && have_v6) {
                continue;
            }
            if let Ok(reflexive) = discover(socket, addr, 5, Duration::from_secs(1)).await {
                if reflexive.is_ipv4() {
                    have_v4 = true;
                } else {
                    have_v6 = true;
                }
                out.push(StunBinding { server: addr, reflexive });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout() {
        let (msg, txid) = binding_request();
        assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 0);
        assert_eq!(u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]), MAGIC_COOKIE);
        assert_eq!(&msg[8..20], &txid);
    }

    #[test]
    fn parses_oracle_xor_mapped_vector() {
        // Vector produced by testing/nat-sim/hyrlm.py stun_binding_response(
        //   txid=00..0b, "198.51.100.20", 41234)
        let pkt = hex(
            "0101000c2112a442000102030405060708090a0b0020000800018000e721c056",
        );
        let txid: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let sa = parse_binding_response(&pkt, &txid).unwrap();
        assert_eq!(sa, "198.51.100.20:41234".parse().unwrap());
    }

    #[test]
    fn rejects_wrong_txid_and_cookie() {
        let pkt = hex(
            "0101000c2112a442000102030405060708090a0b0020000800018000e721c056",
        );
        let wrong: [u8; 12] = [9; 12];
        assert!(parse_binding_response(&pkt, &wrong).is_err());

        let mut bad = pkt.clone();
        bad[4] ^= 0xff; // corrupt cookie
        let txid: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        assert!(parse_binding_response(&bad, &txid).is_err());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
