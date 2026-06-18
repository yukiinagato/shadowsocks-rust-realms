//! The rendezvous HTTP client (Phase 1).
//!
//! Speaks the `hysteria-realm-server` API over `reqwest`:
//!
//! | call | method / path | auth |
//! |---|---|---|
//! | [`register`](RendezvousClient::register)         | `POST /v1/{realm}`            | token |
//! | [`heartbeat`](RendezvousClient::heartbeat)       | `POST /v1/{realm}/heartbeat` | session |
//! | [`connect`](RendezvousClient::connect)           | `POST /v1/{realm}/connect`   | token |
//! | [`post_connects`](RendezvousClient::post_connects) | `POST /v1/{realm}/connects/{nonce}` | session |
//! | [`poll_event`](RendezvousClient::poll_event)     | `GET  /v1/{realm}/events`    | session |
//! | [`delete`](RendezvousClient::delete)             | `DELETE /v1/{realm}`         | session |

use std::time::Duration;

use reqwest::Client;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::url::RealmUrl;

use super::events::{self, RendezvousEvent};
use super::types::{ConnectBody, RegisterRequest, RegisterResponse};

/// Rendezvous HTTP/SSE client bound to a single realm.
#[derive(Debug, Clone)]
pub struct RendezvousClient {
    /// The parsed rendezvous locator (token, host, realm, scheme).
    pub url: RealmUrl,
    http: Client,
    base: String,
}

impl RendezvousClient {
    /// Create a client for the given realm locator.
    ///
    /// The HTTP client is built with proxies disabled: rendezvous traffic is
    /// direct (and the test mock runs on loopback), matching the reference
    /// peer's behaviour.
    pub fn new(url: RealmUrl) -> Result<Self> {
        Self::with_options(url, false)
    }

    /// Like [`new`](Self::new) but, when `insecure` is set, skips TLS
    /// certificate verification for the rendezvous HTTPS connection — the
    /// counterpart of the carrier's `insecure` mode, for a self-hosted Go
    /// `hysteria-realm-server` using a self-signed certificate over `realm://`.
    pub fn with_options(url: RealmUrl, insecure: bool) -> Result<Self> {
        let mut builder = Client::builder().no_proxy();
        if insecure {
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        let http = builder
            .build()
            .map_err(|e| Error::Rendezvous(format!("building http client: {e}")))?;
        let base = url.base_http_url();
        Ok(Self { url, http, base })
    }

    fn realm(&self) -> &str {
        &self.url.realm
    }

    /// `POST /v1/{realm}` — register the server's candidate addresses.
    pub async fn register(&self, addresses: Vec<String>) -> Result<RegisterResponse> {
        let u = format!("{}/v1/{}", self.base, self.realm());
        let resp = self
            .http
            .post(&u)
            .bearer_auth(&self.url.token)
            .json(&RegisterRequest { addresses })
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(map_err)?;
        json_ok(resp).await
    }

    /// `POST /v1/{realm}/heartbeat` — refresh the TTL, optionally replacing the
    /// registered addresses.
    pub async fn heartbeat(&self, session_id: &str, addresses: Option<Vec<String>>) -> Result<()> {
        let u = format!("{}/v1/{}/heartbeat", self.base, self.realm());
        let mut req = self
            .http
            .post(&u)
            .bearer_auth(session_id)
            .timeout(Duration::from_secs(15));
        if let Some(addresses) = addresses {
            req = req.json(&RegisterRequest { addresses });
        }
        ensure_ok(req.send().await.map_err(map_err)?).await
    }

    /// `POST /v1/{realm}/connect` — client asks to connect. Blocks server-side
    /// up to ~10 s for the server to post fresh addresses; returns the peer's
    /// `{addresses, nonce, obfs}`.
    pub async fn connect(&self, body: &ConnectBody) -> Result<ConnectBody> {
        let u = format!("{}/v1/{}/connect", self.base, self.realm());
        let resp = self
            .http
            .post(&u)
            .bearer_auth(&self.url.token)
            .json(body)
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .map_err(map_err)?;
        json_ok(resp).await
    }

    /// `POST /v1/{realm}/connects/{nonce}` — server posts fresh STUN addresses
    /// in response to a `punch` event.
    pub async fn post_connects(
        &self,
        session_id: &str,
        nonce: &str,
        addresses: Vec<String>,
    ) -> Result<()> {
        let u = format!("{}/v1/{}/connects/{}", self.base, self.realm(), nonce);
        let resp = self
            .http
            .post(&u)
            .bearer_auth(session_id)
            .json(&RegisterRequest { addresses })
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(map_err)?;
        ensure_ok(resp).await
    }

    /// `DELETE /v1/{realm}` — deregister.
    pub async fn delete(&self, session_id: &str) -> Result<()> {
        let u = format!("{}/v1/{}", self.base, self.realm());
        let resp = self
            .http
            .delete(&u)
            .bearer_auth(session_id)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(map_err)?;
        ensure_ok(resp).await
    }

    /// `GET /v1/{realm}/events` — return the next event.
    ///
    /// Transparently handles both a `text/event-stream` (real server) and a
    /// single-JSON-object long-poll (testbed mock), so one call yields one event.
    pub async fn poll_event(&self, session_id: &str) -> Result<RendezvousEvent> {
        use futures::StreamExt;

        let u = format!("{}/v1/{}/events", self.base, self.realm());
        let resp = self
            .http
            .get(&u)
            .bearer_auth(session_id)
            .timeout(Duration::from_secs(35))
            .send()
            .await
            .map_err(map_err)?;
        let resp = check_status(resp).await?;

        let is_sse = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/event-stream"))
            .unwrap_or(false);

        if is_sse {
            let mut buf = String::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(map_err)?;
                buf.push_str(&String::from_utf8_lossy(&chunk));
                if let Some(ev) = events::take_first_sse_event(&mut buf)? {
                    return Ok(ev);
                }
            }
            Err(Error::Rendezvous("event stream closed before an event".into()))
        } else {
            let text = resp.text().await.map_err(map_err)?;
            events::parse_longpoll_event(&text)
        }
    }
}

fn map_err(e: reqwest::Error) -> Error {
    Error::Rendezvous(e.to_string())
}

async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(Error::Rendezvous(format!("HTTP {status}: {body}")))
    }
}

async fn ensure_ok(resp: reqwest::Response) -> Result<()> {
    check_status(resp).await?;
    Ok(())
}

async fn json_ok<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let resp = check_status(resp).await?;
    resp.json::<T>().await.map_err(map_err)
}
