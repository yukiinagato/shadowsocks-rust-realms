//! End-to-end orchestration of a realm transport session (Phases 1–4 combined).
//!
//! [`client_connect`] and [`server_accept`] tie together the rendezvous client,
//! STUN discovery, the hole punch, and the QUIC carrier handshake, yielding a
//! ready [`QuicCarrier`]. They are protocol-agnostic — the shadowsocks AEAD layer
//! runs on top in the `shadowsocks` crate.
//!
//! `server_accept` handles a **single** incoming client (punch then QUIC accept
//! over the same socket). Serving many concurrent clients on one registered port
//! requires demultiplexing punch and QUIC packets on a shared socket — see the
//! roadmap. For one client (and the integration tests) this is sufficient.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::quic::{self, QuicCarrier};
use crate::rendezvous::client::RendezvousClient;
use crate::rendezvous::events::RendezvousEvent;
use crate::rendezvous::types::ConnectBody;
use crate::socket::PunchedSocket;
use crate::url::RealmUrl;
use crate::{random_session, stun};

/// Client-side connection parameters.
#[derive(Debug, Clone)]
pub struct ClientParams {
    /// `realm://token@host/realm` locator.
    pub rendezvous: String,
    /// Additional STUN servers (merged with any in the URL).
    pub stun_servers: Vec<String>,
    /// How to verify the QUIC carrier certificate (pin its SHA-256, or accept
    /// any in `Insecure` mode).
    pub tls: crate::quic::ClientTls,
    /// Optional fixed local UDP port.
    pub lport: Option<u16>,
    /// Punch deadline.
    pub punch_deadline: Duration,
}

/// Server-side acceptance parameters.
pub struct ServerParams {
    /// `realm://token@host/realm` locator.
    pub rendezvous: String,
    /// Additional STUN servers (merged with any in the URL).
    pub stun_servers: Vec<String>,
    /// The carrier certificate to present.
    pub cert: CertificateDer<'static>,
    /// The carrier private key.
    pub key: PrivateKeyDer<'static>,
    /// Optional fixed local UDP port.
    pub lport: Option<u16>,
    /// Punch deadline.
    pub punch_deadline: Duration,
}

async fn discover_addresses(socket: &UdpSocket, stun_servers: &[String]) -> Vec<String> {
    let mut addrs: Vec<String> = stun::discover_all(socket, stun_servers)
        .await
        .iter()
        .map(|b| b.reflexive.to_string())
        .collect();
    addrs.sort();
    addrs.dedup();
    if addrs.is_empty()
        && let Ok(local) = socket.local_addr()
    {
        addrs.push(local.to_string());
    }
    addrs
}

/// Run the full client dance and return an established QUIC carrier.
pub async fn client_connect(params: ClientParams) -> Result<QuicCarrier> {
    let url = RealmUrl::parse(&params.rendezvous)?;
    let mut stun_servers = url.stun_servers.clone();
    stun_servers.extend(params.stun_servers.iter().cloned());
    let bind_port = params.lport.or(url.lport).unwrap_or(0);

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, bind_port)).await?;
    let addresses = discover_addresses(&socket, &stun_servers).await;

    let keys = random_session();
    let rc = RendezvousClient::new(url)?;
    let peer = rc
        .connect(&ConnectBody {
            addresses,
            nonce: keys.nonce_hex.clone(),
            obfs: keys.obfs_hex.clone(),
        })
        .await?;

    let peer_addrs = parse_addrs(&peer.addresses)?;
    let punched =
        PunchedSocket::connect(socket, &peer_addrs, &keys.nonce, &keys.obfs, params.punch_deadline)
            .await?;
    quic::connect_client(punched, params.tls).await
}

/// Register a realm and accept a single client, returning its QUIC carrier.
pub async fn server_accept(params: ServerParams) -> Result<QuicCarrier> {
    let url = RealmUrl::parse(&params.rendezvous)?;
    let mut stun_servers = url.stun_servers.clone();
    stun_servers.extend(params.stun_servers.iter().cloned());
    let bind_port = params.lport.or(url.lport).unwrap_or(0);

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, bind_port)).await?;
    let addresses = discover_addresses(&socket, &stun_servers).await;

    let rc = RendezvousClient::new(url)?;
    let reg = rc.register(addresses).await?;
    let session_id = reg.session_id;

    // Wait for a punch request.
    let punch = loop {
        match rc.poll_event(&session_id).await? {
            RendezvousEvent::Punch(cb) => break cb,
            RendezvousEvent::HeartbeatAck => continue,
        }
    };

    // Re-discover fresh addresses and answer the connect.
    let fresh = discover_addresses(&socket, &stun_servers).await;
    rc.post_connects(&session_id, &punch.nonce, fresh).await?;

    let nonce = decode_n::<16>(&punch.nonce, "nonce")?;
    let obfs = decode_n::<32>(&punch.obfs, "obfs")?;
    let peer_addrs = parse_addrs(&punch.addresses)?;
    let punched =
        PunchedSocket::connect(socket, &peer_addrs, &nonce, &obfs, params.punch_deadline).await?;
    quic::accept_server(punched, params.cert, params.key).await
}

/// A long-lived server registration that accepts **many** clients concurrently.
///
/// Registers once, keeps the registration alive with a heartbeat, then hands out
/// one [`QuicCarrier`] per [`accept`](RealmServerRegistration::accept). Each
/// client gets its **own fresh UDP socket** (fresh STUN reflexive address posted
/// via `connects`), so there is no shared-socket demultiplexing — exactly the
/// per-connection model the Realms rendezvous protocol is built for.
pub struct RealmServerRegistration {
    rc: RendezvousClient,
    session_id: String,
    stun_servers: Vec<String>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    punch_deadline: Duration,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

impl RealmServerRegistration {
    /// Register with the rendezvous and start the heartbeat keepalive.
    pub async fn register(params: ServerParams) -> Result<Self> {
        let url = RealmUrl::parse(&params.rendezvous)?;
        let mut stun_servers = url.stun_servers.clone();
        stun_servers.extend(params.stun_servers.iter().cloned());
        let bind_port = params.lport.or(url.lport).unwrap_or(0);

        // A socket only to learn an initial reflexive address for registration;
        // each accepted client later uses its own fresh socket.
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, bind_port)).await?;
        let addresses = discover_addresses(&socket, &stun_servers).await;
        drop(socket);

        let rc = RendezvousClient::new(url)?;
        let reg = rc.register(addresses).await?;
        let session_id = reg.session_id;
        let ttl = reg.ttl.max(10);

        let hb_rc = rc.clone();
        let hb_sid = session_id.clone();
        let heartbeat = tokio::spawn(async move {
            let interval = Duration::from_secs((ttl / 2).max(5));
            loop {
                tokio::time::sleep(interval).await;
                let _ = hb_rc.heartbeat(&hb_sid, None).await;
            }
        });

        Ok(Self {
            rc,
            session_id,
            stun_servers,
            cert: params.cert,
            key: params.key,
            punch_deadline: params.punch_deadline,
            heartbeat: Some(heartbeat),
        })
    }

    /// Wait for the next client's punch request (one rendezvous event).
    pub async fn next_punch(&self) -> Result<ConnectBody> {
        loop {
            match self.rc.poll_event(&self.session_id).await? {
                RendezvousEvent::Punch(cb) => return Ok(cb),
                RendezvousEvent::HeartbeatAck => continue,
            }
        }
    }

    /// Complete one client's punch + QUIC handshake on a fresh socket. Safe to
    /// run concurrently for many clients (each uses its own socket).
    pub async fn handle_punch(&self, punch: ConnectBody) -> Result<QuicCarrier> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        let fresh = discover_addresses(&socket, &self.stun_servers).await;
        self.rc.post_connects(&self.session_id, &punch.nonce, fresh).await?;

        let nonce = decode_n::<16>(&punch.nonce, "nonce")?;
        let obfs = decode_n::<32>(&punch.obfs, "obfs")?;
        let peer_addrs = parse_addrs(&punch.addresses)?;
        let punched =
            PunchedSocket::connect(socket, &peer_addrs, &nonce, &obfs, self.punch_deadline).await?;
        quic::accept_server(punched, self.cert.clone(), self.key.clone_key()).await
    }

    /// Convenience: wait for one client and complete its handshake.
    pub async fn accept(&self) -> Result<QuicCarrier> {
        let punch = self.next_punch().await?;
        self.handle_punch(punch).await
    }
}

impl Drop for RealmServerRegistration {
    fn drop(&mut self) {
        if let Some(h) = self.heartbeat.take() {
            h.abort();
        }
    }
}

fn parse_addrs(v: &[String]) -> Result<Vec<SocketAddr>> {
    let out: Vec<SocketAddr> = v.iter().filter_map(|s| s.parse().ok()).collect();
    if out.is_empty() {
        return Err(Error::Punch("no usable peer addresses".into()));
    }
    Ok(out)
}

fn decode_n<const N: usize>(h: &str, what: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(h).map_err(|_| Error::Punch(format!("bad {what} hex")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Punch(format!("{what} wrong length")))
}
