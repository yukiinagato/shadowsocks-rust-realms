//! Realm transport bridge (feature `realm`): run the shadowsocks AEAD proxy
//! protocol over the QUIC carrier from the `shadowsocks-realm` crate.
//!
//! The shadowsocks stream types ([`ProxyClientStream`] / [`ProxyServerStream`])
//! are generic over any `AsyncRead + AsyncWrite` transport, so a QUIC bidi
//! stream carries the encrypted proxy protocol unchanged. One bidi stream is
//! opened per proxied TCP connection.
//!
//! This module is the seam between `shadowsocks-realm` (transport) and the rest
//! of the shadowsocks crate (ss protocol + relay). The higher-level sslocal /
//! ssserver wiring lives in `shadowsocks-service`.

use std::io;
use std::sync::Arc;

use quinn::{RecvStream, SendStream};
use tokio::io::Join;
use tokio::net::TcpStream;

use shadowsocks_crypto::CipherKind;
use shadowsocks_realm::path_manager::PathManager;
use shadowsocks_realm::quic::QuicCarrier;
use shadowsocks_realm::session::{ClientParams, ServerParams, client_connect, server_accept};

use crate::config::ServerConfig;
use crate::context::SharedContext;
use crate::relay::Address;
use crate::relay::tcprelay::utils::copy_encrypted_bidirectional;
use crate::relay::tcprelay::{ProxyClientStream, ProxyServerStream};

// Re-export the transport crate so downstream code has one import path.
pub use shadowsocks_realm;

/// A bidirectional QUIC stream presented as a single `AsyncRead + AsyncWrite`
/// duplex (read half = `RecvStream`, write half = `SendStream`).
pub type RealmStream = Join<RecvStream, SendStream>;

/// Adapt a quinn bidi pair into a single duplex [`RealmStream`].
pub fn join_bi(send: SendStream, recv: RecvStream) -> RealmStream {
    tokio::io::join(recv, send)
}

/// Client: open a new proxied stream to `target` over the carrier. The returned
/// [`ProxyClientStream`] speaks shadowsocks AEAD over the QUIC bidi stream.
pub async fn open_proxied<A>(
    context: SharedContext,
    carrier: &QuicCarrier,
    svr_cfg: &ServerConfig,
    target: A,
) -> io::Result<ProxyClientStream<RealmStream>>
where
    A: Into<Address>,
{
    let (send, recv) = carrier
        .connection()
        .open_bi()
        .await
        .map_err(io::Error::other)?;
    let stream = join_bi(send, recv);
    Ok(ProxyClientStream::from_stream(
        context, stream, svr_cfg, target,
    ))
}

/// Server: accept the next proxied stream, perform the shadowsocks handshake,
/// and return the server stream together with the client's requested target.
pub async fn accept_proxied(
    context: SharedContext,
    carrier: &QuicCarrier,
    method: CipherKind,
    key: &[u8],
) -> io::Result<(ProxyServerStream<RealmStream>, Address)> {
    let (send, recv) = carrier
        .connection()
        .accept_bi()
        .await
        .map_err(io::Error::other)?;
    let stream = join_bi(send, recv);
    let mut ss = ProxyServerStream::from_stream(context, stream, method, key);
    let target = ss.handshake().await?;
    Ok((ss, target))
}

/// Client-side realm transport for one remote ss server: establishes the carrier
/// (rendezvous + STUN + punch + QUIC) and opens a proxied ss stream per request.
///
/// The [`PathManager`] tracks an optional direct-TCP upgrade (PATH B); native-TCP
/// dialing is wired by `shadowsocks-service` (which owns `ConnectOpts`).
pub struct RealmClient {
    context: SharedContext,
    svr_cfg: ServerConfig,
    carrier: QuicCarrier,
    path_manager: Arc<PathManager>,
}

impl RealmClient {
    /// Run the full client dance and hold the resulting carrier.
    pub async fn connect(
        context: SharedContext,
        svr_cfg: ServerConfig,
        params: ClientParams,
        prefer_tcp: bool,
    ) -> io::Result<Self> {
        let carrier = client_connect(params).await.map_err(io::Error::other)?;
        Ok(Self {
            context,
            svr_cfg,
            carrier,
            path_manager: Arc::new(PathManager::new(prefer_tcp)),
        })
    }

    /// Open a proxied ss stream to `target` over the carrier (PATH A / QUIC).
    pub async fn connect_target<A>(&self, target: A) -> io::Result<ProxyClientStream<RealmStream>>
    where
        A: Into<Address>,
    {
        open_proxied(self.context.clone(), &self.carrier, &self.svr_cfg, target).await
    }

    /// The path manager driving QUIC↔TCP selection for new connections.
    pub fn path_manager(&self) -> &Arc<PathManager> {
        &self.path_manager
    }

    /// Close the carrier.
    pub async fn close(&self) {
        self.carrier.close().await;
    }
}

/// Server-side realm transport for one ss server: registers the realm, accepts a
/// punched QUIC carrier, and relays accepted ss streams to their targets.
pub struct RealmServer {
    context: SharedContext,
    svr_cfg: ServerConfig,
    carrier: QuicCarrier,
}

impl RealmServer {
    /// Register the realm and accept a single client's carrier.
    pub async fn accept(
        context: SharedContext,
        svr_cfg: ServerConfig,
        params: ServerParams,
    ) -> io::Result<Self> {
        let carrier = server_accept(params).await.map_err(io::Error::other)?;
        Ok(Self { context, svr_cfg, carrier })
    }

    /// Serve proxied streams until the carrier closes: handshake each stream,
    /// dial its target over TCP, and relay with the existing encrypted-copy loop.
    pub async fn serve(&self) -> io::Result<()> {
        let method = self.svr_cfg.method();
        loop {
            let (mut ss, target) = match accept_proxied(
                self.context.clone(),
                &self.carrier,
                method,
                self.svr_cfg.key(),
            )
            .await
            {
                Ok(v) => v,
                Err(_) => return Ok(()), // carrier closed
            };
            tokio::spawn(async move {
                if let Ok(mut remote) = TcpStream::connect(target.to_string()).await {
                    let _ = copy_encrypted_bidirectional(method, &mut ss, &mut remote).await;
                }
            });
        }
    }

    /// The established carrier.
    pub fn carrier(&self) -> &QuicCarrier {
        &self.carrier
    }
}
