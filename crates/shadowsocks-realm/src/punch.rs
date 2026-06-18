//! `HYRLMv1` punch codec and Hello/Ack punch loop (Phase 3).
//!
//! The wire format is byte-exact with `apernet/hysteria`
//! (`extras/realm/punch.go`) so our nodes interoperate with peers punched via
//! the stock rendezvous server:
//!
//! ```text
//! [8 bytes]  salt (random per packet)
//! [payload]  XOR-obfuscated, mask = SHA256(obfsKey || salt), repeating 32B
//!   plain payload (25-byte header + 0..1024 random padding):
//!     [8]  magic = "HYRLMv1\0"
//!     [1]  type: 0x01 Hello, 0x02 Ack
//!     [16] nonce (must equal the connect nonce)
//!     [N]  random padding, 0..1024 bytes
//! ```
//!
//! Validated byte-for-byte against `testing/nat-sim/hyrlm.py`.

use std::net::SocketAddr;
use std::time::Duration;

use rand::RngExt;
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

use crate::HYRLM_MAGIC;
use crate::error::{Error, Result};

/// Length of the random per-packet salt prefix.
pub const SALT_LEN: usize = 8;
/// Length of the nonce shared between peers (16 bytes, 32 hex chars on the wire).
pub const NONCE_LEN: usize = 16;
/// Length of the obfuscation key (32 bytes, 64 hex chars on the wire).
pub const OBFS_LEN: usize = 32;
/// Fixed plaintext header length: 8 (magic) + 1 (type) + 16 (nonce).
pub const HEADER_LEN: usize = 25;
/// Minimum valid wire length: salt + header.
pub const MIN_WIRE_LEN: usize = SALT_LEN + HEADER_LEN; // 33
/// Maximum padding appended after the header.
pub const MAX_PADDING: usize = 1024;
/// Maximum valid wire length.
pub const MAX_WIRE_LEN: usize = MIN_WIRE_LEN + MAX_PADDING; // 1057

/// Punch packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PunchType {
    /// Initial punch probe.
    Hello = 0x01,
    /// Acknowledgement of a received `Hello`.
    Ack = 0x02,
}

impl PunchType {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(PunchType::Hello),
            0x02 => Some(PunchType::Ack),
            _ => None,
        }
    }
}

fn mask(obfs: &[u8; OBFS_LEN], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(obfs);
    h.update(salt);
    h.finalize().into()
}

/// Encode a punch packet with the given salt and padding (deterministic).
///
/// Exposed mainly for testing against fixed oracle vectors; production code uses
/// [`encode`], which randomises the salt and padding length.
pub fn encode_with(
    ptype: PunchType,
    nonce: &[u8; NONCE_LEN],
    obfs: &[u8; OBFS_LEN],
    salt: &[u8; SALT_LEN],
    padding: &[u8],
) -> Vec<u8> {
    let mut plain = Vec::with_capacity(HEADER_LEN + padding.len());
    plain.extend_from_slice(&HYRLM_MAGIC);
    plain.push(ptype as u8);
    plain.extend_from_slice(nonce);
    plain.extend_from_slice(padding);

    let m = mask(obfs, salt);
    for (i, b) in plain.iter_mut().enumerate() {
        *b ^= m[i % 32];
    }

    let mut out = Vec::with_capacity(SALT_LEN + plain.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&plain);
    out
}

/// Encode a punch packet with a random salt and random padding length
/// (0..=1024), matching the reference implementation's anti-fingerprinting.
pub fn encode(ptype: PunchType, nonce: &[u8; NONCE_LEN], obfs: &[u8; OBFS_LEN]) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt[..]);
    let pad_len = rng.random_range(0..=MAX_PADDING);
    let mut padding = vec![0u8; pad_len];
    rng.fill(&mut padding[..]);
    encode_with(ptype, nonce, obfs, &salt, &padding)
}

/// Decode and validate a punch packet, returning its type and padding length.
///
/// Returns [`Error::Punch`] on bad length, bad magic, unknown type, or nonce
/// mismatch — exactly the cases the reference discards.
pub fn decode(
    packet: &[u8],
    nonce: &[u8; NONCE_LEN],
    obfs: &[u8; OBFS_LEN],
) -> Result<(PunchType, usize)> {
    if !(MIN_WIRE_LEN..=MAX_WIRE_LEN).contains(&packet.len()) {
        return Err(Error::Punch(format!("bad length {}", packet.len())));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&packet[..SALT_LEN]);
    let mut body = packet[SALT_LEN..].to_vec();

    let m = mask(obfs, &salt);
    for (i, b) in body.iter_mut().enumerate() {
        *b ^= m[i % 32];
    }

    if body[0..8] != HYRLM_MAGIC {
        return Err(Error::Punch("bad magic".into()));
    }
    let ptype = PunchType::from_u8(body[8]).ok_or_else(|| Error::Punch("bad type".into()))?;
    if body[9..25] != nonce[..] {
        return Err(Error::Punch("nonce mismatch".into()));
    }
    Ok((ptype, body.len() - HEADER_LEN))
}

/// Symmetric Hello/Ack hole-punch loop over `socket` toward `peers`.
///
/// Fires `Hello` at every candidate address at a fixed interval; answers each
/// valid `Hello` with an `Ack`; on the first valid `Ack` confirms that source as
/// the peer, sends a few trailing `Ack`s (so the peer also confirms), and
/// returns the confirmed address. Errors with [`Error::PunchTimeout`] if no peer
/// confirms before `deadline` (typically symmetric NAT on both ends).
pub async fn punch(
    socket: &UdpSocket,
    peers: &[SocketAddr],
    nonce: &[u8; NONCE_LEN],
    obfs: &[u8; OBFS_LEN],
    deadline: Duration,
) -> Result<SocketAddr> {
    let end = Instant::now() + deadline;
    let mut buf = [0u8; 2048];
    let mut last_send: Option<Instant> = None;
    let mut confirmed: Option<SocketAddr> = None;

    while Instant::now() < end && confirmed.is_none() {
        let due = last_send.is_none_or(|t| t.elapsed() > Duration::from_millis(250));
        if due {
            let hello = encode(PunchType::Hello, nonce, obfs);
            for &p in peers {
                let _ = socket.send_to(&hello, p).await;
            }
            last_send = Some(Instant::now());
        }

        match timeout(Duration::from_millis(200), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => match decode(&buf[..n], nonce, obfs) {
                Ok((PunchType::Hello, _)) => {
                    log::debug!("punch: got Hello from {src}, replying Ack");
                    let ack = encode(PunchType::Ack, nonce, obfs);
                    let _ = socket.send_to(&ack, src).await;
                }
                Ok((PunchType::Ack, _)) => {
                    log::debug!("punch: got Ack from {src} — hole OPEN");
                    confirmed = Some(src);
                }
                Err(_) => {
                    log::trace!("punch: discarded {n}B from {src} (not a punch packet for us)");
                }
            },
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {} // recv timed out; loop to maybe resend
        }
    }

    let peer = confirmed.ok_or_else(|| {
        log::warn!("punch: timed out — no Ack received from any of {peers:?}");
        Error::PunchTimeout
    })?;
    let ack = encode(PunchType::Ack, nonce, obfs);
    for _ in 0..5 {
        let _ = socket.send_to(&ack, peer).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> [u8; 16] {
        let mut n = [0u8; 16];
        for (i, b) in n.iter_mut().enumerate() {
            *b = i as u8;
        }
        n
    }
    fn obfs() -> [u8; 32] {
        let mut o = [0u8; 32];
        for (i, b) in o.iter_mut().enumerate() {
            *b = i as u8;
        }
        o
    }
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn encodes_byte_exact_oracle_vectors() {
        let salt: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
        let pad: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];

        // Vectors from testing/nat-sim/hyrlm.py (blessed by its decode_punch).
        let hello = encode_with(PunchType::Hello, &nonce(), &obfs(), &salt, &pad);
        assert_eq!(
            hello,
            hex("0001020304050607ddb1e7f48fd239aea4f289063a5edb7e5d0631060590fecf214e3c3998")
        );
        let ack = encode_with(PunchType::Ack, &nonce(), &obfs(), &salt, &pad);
        assert_eq!(
            ack,
            hex("0001020304050607ddb1e7f48fd239aea7f289063a5edb7e5d0631060590fecf214e3c3998")
        );
    }

    #[test]
    fn decodes_oracle_vectors() {
        let hello =
            hex("0001020304050607ddb1e7f48fd239aea4f289063a5edb7e5d0631060590fecf214e3c3998");
        assert_eq!(decode(&hello, &nonce(), &obfs()).unwrap(), (PunchType::Hello, 4));
        let ack =
            hex("0001020304050607ddb1e7f48fd239aea7f289063a5edb7e5d0631060590fecf214e3c3998");
        assert_eq!(decode(&ack, &nonce(), &obfs()).unwrap(), (PunchType::Ack, 4));
    }

    #[test]
    fn round_trip_random() {
        for ptype in [PunchType::Hello, PunchType::Ack] {
            let pkt = encode(ptype, &nonce(), &obfs());
            assert!((MIN_WIRE_LEN..=MAX_WIRE_LEN).contains(&pkt.len()));
            let (decoded, _pad) = decode(&pkt, &nonce(), &obfs()).unwrap();
            assert_eq!(decoded, ptype);
        }
    }

    #[test]
    fn rejects_tampered_and_wrong_nonce() {
        let mut pkt = encode(PunchType::Hello, &nonce(), &obfs());
        // wrong nonce
        let mut other = nonce();
        other[0] ^= 0xff;
        assert!(decode(&pkt, &other, &obfs()).is_err());
        // tamper a header byte -> bad magic after de-XOR
        pkt[SALT_LEN] ^= 0xff;
        assert!(decode(&pkt, &nonce(), &obfs()).is_err());
        // bad length
        assert!(decode(&pkt[..10], &nonce(), &obfs()).is_err());
    }
}
