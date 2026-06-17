//! NAT-PMP external TCP port mapping (RFC 6886), for routers that speak NAT-PMP
//! rather than UPnP — notably many Apple / consumer routers (Phase 5).
//!
//! Only the subset we need is implemented: the external-address request and the
//! TCP map request, with a small retry loop. PCP (RFC 6887) shares the UDP/5351
//! transport and can be layered on later.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::PortMapping;
use crate::error::{Error, Result};

/// The well-known NAT-PMP server port on the gateway.
pub const NATPMP_PORT: u16 = 5351;

const OP_MAP_TCP: u8 = 2;

/// Encode an external-address request (`[version=0][op=0]`).
pub fn encode_external_address_request() -> [u8; 2] {
    [0, 0]
}

/// Parse an external-address response, returning the public IPv4 address.
pub fn parse_external_address_response(buf: &[u8]) -> Result<Ipv4Addr> {
    if buf.len() < 12 {
        return Err(Error::PortMap("short external-address response".into()));
    }
    if buf[0] != 0 {
        return Err(Error::PortMap(format!("unexpected version {}", buf[0])));
    }
    if buf[1] != 128 {
        return Err(Error::PortMap(format!("unexpected opcode {}", buf[1])));
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    if result != 0 {
        return Err(Error::PortMap(format!("result code {result}")));
    }
    Ok(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
}

/// Encode a TCP map request:
/// `[ver=0][op=2][reserved=0:2][internal:2][external:2][lease:4]`.
pub fn encode_map_request(internal_port: u16, external_port: u16, lease_secs: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = 0;
    b[1] = OP_MAP_TCP;
    // b[2..4] reserved = 0
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&external_port.to_be_bytes());
    b[8..12].copy_from_slice(&lease_secs.to_be_bytes());
    b
}

/// Parse a map response, returning `(internal_port, mapped_external_port, lease)`.
pub fn parse_map_response(buf: &[u8]) -> Result<(u16, u16, u32)> {
    if buf.len() < 16 {
        return Err(Error::PortMap("short map response".into()));
    }
    if buf[0] != 0 {
        return Err(Error::PortMap(format!("unexpected version {}", buf[0])));
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    if result != 0 {
        return Err(Error::PortMap(format!("result code {result}")));
    }
    let internal = u16::from_be_bytes([buf[8], buf[9]]);
    let external = u16::from_be_bytes([buf[10], buf[11]]);
    let lease = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    Ok((internal, external, lease))
}

/// Request a TCP mapping from `gateway`. A `lease_secs` of 0 removes the mapping.
pub async fn map_tcp(
    gateway: Ipv4Addr,
    internal_port: u16,
    requested_external_port: u16,
    lease_secs: u32,
    per_try: Duration,
    retries: usize,
) -> Result<PortMapping> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((gateway, NATPMP_PORT)).await?;

    let external_ip = request_external_address(&sock, per_try, retries).await?;

    let req = encode_map_request(internal_port, requested_external_port, lease_secs);
    let mut buf = [0u8; 32];
    for _ in 0..retries.max(1) {
        sock.send(&req).await?;
        match timeout(per_try, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Ok((_in, ext_port, _lease)) = parse_map_response(&buf[..n]) {
                    return Ok(PortMapping {
                        external: SocketAddr::new(external_ip.into(), ext_port),
                        internal_port,
                    });
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {} // retry
        }
    }
    Err(Error::PortMap(format!("no NAT-PMP map response from {gateway}")))
}

async fn request_external_address(
    sock: &UdpSocket,
    per_try: Duration,
    retries: usize,
) -> Result<Ipv4Addr> {
    let req = encode_external_address_request();
    let mut buf = [0u8; 32];
    for _ in 0..retries.max(1) {
        sock.send(&req).await?;
        match timeout(per_try, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Ok(ip) = parse_external_address_response(&buf[..n]) {
                    return Ok(ip);
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {}
        }
    }
    Err(Error::PortMap("no NAT-PMP external-address response".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_address_request_layout() {
        assert_eq!(encode_external_address_request(), [0u8, 0u8]);
    }

    #[test]
    fn map_request_layout() {
        let b = encode_map_request(8388, 9000, 7200);
        assert_eq!(b[0], 0); // version
        assert_eq!(b[1], OP_MAP_TCP); // TCP map
        assert_eq!(&b[2..4], &[0, 0]); // reserved
        assert_eq!(u16::from_be_bytes([b[4], b[5]]), 8388);
        assert_eq!(u16::from_be_bytes([b[6], b[7]]), 9000);
        assert_eq!(u32::from_be_bytes([b[8], b[9], b[10], b[11]]), 7200);
    }

    #[test]
    fn parses_map_and_external_responses() {
        // external-address success: ver=0 op=128 result=0 epoch=1 ip=203.0.113.7
        let ext = [0u8, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 7];
        assert_eq!(parse_external_address_response(&ext).unwrap(), Ipv4Addr::new(203, 0, 113, 7));

        // map success: ver=0 op=130 result=0 epoch=1 internal=8388 external=9000 lease=7200
        let mut m = vec![0u8, 130, 0, 0, 0, 0, 0, 1];
        m.extend_from_slice(&8388u16.to_be_bytes());
        m.extend_from_slice(&9000u16.to_be_bytes());
        m.extend_from_slice(&7200u32.to_be_bytes());
        assert_eq!(parse_map_response(&m).unwrap(), (8388, 9000, 7200));
    }

    #[test]
    fn rejects_error_result_code() {
        let ext = [0u8, 128, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]; // result=2
        assert!(parse_external_address_response(&ext).is_err());
    }
}
