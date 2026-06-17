//! In-band control protocol over a dedicated QUIC bidi "control" stream (Phase 6).
//!
//! Opened right after the carrier handshake, this small message set lets the
//! server announce a direct-TCP endpoint (PATH B) *over the working QUIC link*,
//! so the unmodified Go rendezvous never needs to know about TCP.
//!
//! Framing (our own protocol — not interop with the Go rendezvous):
//!
//! ```text
//! ControlMsg ::= [type: u8][len: u32 BE][body: len bytes]
//!   0x01 TcpEndpointOffer  body = [n: u8] n×([alen: u16 BE][addr utf8]) [token: 32B]
//!   0x02 TcpEndpointAck    body = [accepted: u8]
//!   0x03 Ping              body = [ts: u64 BE]
//!   0x04 Pong              body = [ts: u64 BE]
//!   0x05 TcpPathDown       body = (empty)
//! ```
//!
//! Encoding/decoding is generic over `AsyncRead`/`AsyncWrite`, so it works over a
//! quinn stream in production and an in-memory duplex in tests.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Length of the session-binding token carried in a TCP endpoint offer.
pub const TOKEN_LEN: usize = 32;

const MAX_BODY: usize = 64 * 1024;

const T_OFFER: u8 = 0x01;
const T_ACK: u8 = 0x02;
const T_PING: u8 = 0x03;
const T_PONG: u8 = 0x04;
const T_PATH_DOWN: u8 = 0x05;

/// A control-stream message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMsg {
    /// server→client: a direct-TCP endpoint is available; `token` binds an
    /// incoming TCP connection to this authenticated session.
    TcpEndpointOffer {
        /// Candidate public `ip:port` addresses for the direct-TCP listener.
        addresses: Vec<String>,
        /// 32-byte session-binding token.
        token: [u8; TOKEN_LEN],
    },
    /// client→server: whether the client accepted the offer.
    TcpEndpointAck {
        /// `true` if the client successfully verified and adopted the TCP path.
        accepted: bool,
    },
    /// keepalive / RTT probe (millisecond timestamp).
    Ping(u64),
    /// reply to [`ControlMsg::Ping`].
    Pong(u64),
    /// either side: the TCP path is down; demote to QUIC.
    TcpPathDown,
}

impl ControlMsg {
    fn type_tag(&self) -> u8 {
        match self {
            ControlMsg::TcpEndpointOffer { .. } => T_OFFER,
            ControlMsg::TcpEndpointAck { .. } => T_ACK,
            ControlMsg::Ping(_) => T_PING,
            ControlMsg::Pong(_) => T_PONG,
            ControlMsg::TcpPathDown => T_PATH_DOWN,
        }
    }

    fn encode_body(&self) -> Vec<u8> {
        match self {
            ControlMsg::TcpEndpointOffer { addresses, token } => {
                let mut b = Vec::new();
                b.push(addresses.len().min(255) as u8);
                for a in addresses.iter().take(255) {
                    let bytes = a.as_bytes();
                    b.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    b.extend_from_slice(bytes);
                }
                b.extend_from_slice(token);
                b
            }
            ControlMsg::TcpEndpointAck { accepted } => vec![*accepted as u8],
            ControlMsg::Ping(ts) | ControlMsg::Pong(ts) => ts.to_be_bytes().to_vec(),
            ControlMsg::TcpPathDown => Vec::new(),
        }
    }

    fn decode(type_tag: u8, body: &[u8]) -> Result<Self> {
        let bad = |m: &str| Error::Rendezvous(format!("control decode: {m}"));
        match type_tag {
            T_OFFER => {
                if body.is_empty() {
                    return Err(bad("empty offer"));
                }
                let n = body[0] as usize;
                let mut off = 1;
                let mut addresses = Vec::with_capacity(n);
                for _ in 0..n {
                    if off + 2 > body.len() {
                        return Err(bad("truncated addr len"));
                    }
                    let alen = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
                    off += 2;
                    if off + alen > body.len() {
                        return Err(bad("truncated addr"));
                    }
                    let s = std::str::from_utf8(&body[off..off + alen])
                        .map_err(|_| bad("addr not utf8"))?
                        .to_string();
                    addresses.push(s);
                    off += alen;
                }
                if off + TOKEN_LEN > body.len() {
                    return Err(bad("missing token"));
                }
                let mut token = [0u8; TOKEN_LEN];
                token.copy_from_slice(&body[off..off + TOKEN_LEN]);
                Ok(ControlMsg::TcpEndpointOffer { addresses, token })
            }
            T_ACK => {
                if body.len() != 1 {
                    return Err(bad("bad ack body"));
                }
                Ok(ControlMsg::TcpEndpointAck { accepted: body[0] != 0 })
            }
            T_PING | T_PONG => {
                if body.len() != 8 {
                    return Err(bad("bad ping/pong body"));
                }
                let ts = u64::from_be_bytes(body.try_into().unwrap());
                Ok(if type_tag == T_PING {
                    ControlMsg::Ping(ts)
                } else {
                    ControlMsg::Pong(ts)
                })
            }
            T_PATH_DOWN => Ok(ControlMsg::TcpPathDown),
            other => Err(bad(&format!("unknown type {other:#04x}"))),
        }
    }
}

/// Write one control message to the stream.
pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &ControlMsg) -> Result<()> {
    let body = msg.encode_body();
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.push(msg.type_tag());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}

/// Read one control message from the stream.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<ControlMsg> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await?;
    let type_tag = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_BODY {
        return Err(Error::Rendezvous(format!("control frame too large: {len}")));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    ControlMsg::decode(type_tag, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn round_trip(msg: ControlMsg) {
        let (mut a, mut b) = tokio::io::duplex(8192);
        write_msg(&mut a, &msg).await.unwrap();
        let got = read_msg(&mut b).await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn round_trips_all_messages() {
        round_trip(ControlMsg::TcpEndpointOffer {
            addresses: vec!["203.0.113.7:9000".into(), "[2001:db8::1]:9000".into()],
            token: [7u8; TOKEN_LEN],
        })
        .await;
        round_trip(ControlMsg::TcpEndpointAck { accepted: true }).await;
        round_trip(ControlMsg::TcpEndpointAck { accepted: false }).await;
        round_trip(ControlMsg::Ping(123456789)).await;
        round_trip(ControlMsg::Pong(987654321)).await;
        round_trip(ControlMsg::TcpPathDown).await;
    }

    #[tokio::test]
    async fn rejects_unknown_type() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // type=0x7f, len=0
        a.write_all(&[0x7f, 0, 0, 0, 0]).await.unwrap();
        a.flush().await.unwrap();
        assert!(read_msg(&mut b).await.is_err());
    }
}
