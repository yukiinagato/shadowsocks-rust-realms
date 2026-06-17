//! Rendezvous event decoding for `GET /v1/{realm}/events`.
//!
//! The production `hysteria-realm-server` streams `text/event-stream` (SSE); the
//! testbed mock (`testing/nat-sim/rendezvous.py`) instead answers each GET with a
//! single JSON object (a one-event long-poll). Both encode the same two event
//! kinds, so we decode both shapes into [`RendezvousEvent`].

use serde::Deserialize;

use crate::error::{Error, Result};

use super::types::ConnectBody;

/// A decoded rendezvous event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendezvousEvent {
    /// A peer is requesting a punch; respond via `POST /connects/{nonce}`.
    Punch(ConnectBody),
    /// A heartbeat was acknowledged.
    HeartbeatAck,
}

/// JSON long-poll event shape used by the testbed mock:
/// `{"event":"punch","addresses":[...],"nonce":"..","obfs":".."}` or
/// `{"event":"heartbeat_ack","ttl":60}`.
#[derive(Debug, Deserialize)]
struct LongPollEvent {
    event: String,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    obfs: String,
}

fn from_parts(kind: &str, addresses: Vec<String>, nonce: String, obfs: String) -> Result<RendezvousEvent> {
    match kind {
        "punch" => Ok(RendezvousEvent::Punch(ConnectBody { addresses, nonce, obfs })),
        "heartbeat_ack" => Ok(RendezvousEvent::HeartbeatAck),
        other => Err(Error::Rendezvous(format!("unknown event kind: {other:?}"))),
    }
}

/// Decode a single JSON long-poll event body (testbed mock).
pub fn parse_longpoll_event(text: &str) -> Result<RendezvousEvent> {
    let e: LongPollEvent = serde_json::from_str(text)
        .map_err(|err| Error::Rendezvous(format!("bad event json: {err}: {text:?}")))?;
    from_parts(&e.event, e.addresses, e.nonce, e.obfs)
}

/// Consume and return the first complete SSE event from `buf`.
///
/// SSE frames are separated by a blank line. Comment-only or unnamed frames
/// (e.g. `: keepalive`) are skipped. Returns `Ok(None)` when no complete frame
/// is buffered yet, so callers can append more bytes and retry.
pub fn take_first_sse_event(buf: &mut String) -> Result<Option<RendezvousEvent>> {
    while let Some(idx) = buf.find("\n\n") {
        let frame = buf[..idx].to_string();
        *buf = buf[idx + 2..].to_string();

        let mut ev_name = String::new();
        let mut data = String::new();
        for raw in frame.lines() {
            let line = raw.trim_end_matches('\r');
            if let Some(v) = line.strip_prefix("event:") {
                ev_name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("data:") {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(v.strip_prefix(' ').unwrap_or(v));
            }
            // lines beginning with ':' are comments — ignored.
        }

        if ev_name.is_empty() {
            continue; // heartbeat/comment frame; look for the next one
        }
        return match ev_name.as_str() {
            "punch" => {
                let body: ConnectBody = serde_json::from_str(&data).map_err(|e| {
                    Error::Rendezvous(format!("bad punch data: {e}: {data:?}"))
                })?;
                Ok(Some(RendezvousEvent::Punch(body)))
            }
            "heartbeat_ack" => Ok(Some(RendezvousEvent::HeartbeatAck)),
            other => Err(Error::Rendezvous(format!("unknown sse event: {other:?}"))),
        };
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longpoll_punch() {
        let t = r#"{"event":"punch","addresses":["1.2.3.4:5"],"nonce":"aa","obfs":"bb"}"#;
        let ev = parse_longpoll_event(t).unwrap();
        assert_eq!(
            ev,
            RendezvousEvent::Punch(ConnectBody {
                addresses: vec!["1.2.3.4:5".into()],
                nonce: "aa".into(),
                obfs: "bb".into(),
            })
        );
    }

    #[test]
    fn longpoll_heartbeat() {
        let ev = parse_longpoll_event(r#"{"event":"heartbeat_ack","ttl":60}"#).unwrap();
        assert_eq!(ev, RendezvousEvent::HeartbeatAck);
    }

    #[test]
    fn sse_punch_after_comment() {
        let mut buf = String::from(
            ": keepalive\n\nevent: punch\ndata: {\"addresses\":[\"9.9.9.9:1\"],\"nonce\":\"n\",\"obfs\":\"o\"}\n\n",
        );
        let ev = take_first_sse_event(&mut buf).unwrap().unwrap();
        assert_eq!(
            ev,
            RendezvousEvent::Punch(ConnectBody {
                addresses: vec!["9.9.9.9:1".into()],
                nonce: "n".into(),
                obfs: "o".into(),
            })
        );
        // nothing complete left
        assert_eq!(take_first_sse_event(&mut buf).unwrap(), None);
    }

    #[test]
    fn sse_partial_then_complete() {
        let mut buf = String::from("event: heartbeat_ack\n");
        assert_eq!(take_first_sse_event(&mut buf).unwrap(), None);
        buf.push('\n');
        assert_eq!(
            take_first_sse_event(&mut buf).unwrap(),
            Some(RendezvousEvent::HeartbeatAck)
        );
    }
}
