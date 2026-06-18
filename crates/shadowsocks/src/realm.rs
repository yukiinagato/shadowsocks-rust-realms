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

use std::collections::HashMap;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use pin_project::pin_project;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, Join, ReadBuf};
use tokio::net::TcpStream;

use shadowsocks_crypto::CipherKind;
use shadowsocks_realm::control::{self, ControlMsg, TOKEN_LEN};
use shadowsocks_realm::path_manager::{Path, PathManager};
use shadowsocks_realm::quic::QuicCarrier;
use shadowsocks_realm::session::{ClientParams, ServerParams, client_connect, server_accept};

use crate::config::ServerConfig;
use crate::context::SharedContext;
use crate::relay::Address;
use crate::relay::tcprelay::utils::copy_encrypted_bidirectional;
use crate::relay::tcprelay::{ProxyClientStream, ProxyServerStream};
use crate::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket, ProxySocket, UdpSocketType};

// Re-export the transport crate so downstream code has one import path.
pub use shadowsocks_realm;

/// A bidirectional QUIC stream presented as a single `AsyncRead + AsyncWrite`
/// duplex (read half = `RecvStream`, write half = `SendStream`).
pub type RealmStream = Join<RecvStream, SendStream>;

/// Adapt a quinn bidi pair into a single duplex [`RealmStream`].
pub fn join_bi(send: SendStream, recv: RecvStream) -> RealmStream {
    tokio::io::join(recv, send)
}

/// A proxied client stream over whichever realm path was selected: the QUIC
/// carrier (PATH A) or a direct shadowsocks-over-TCP connection (PATH B). Both
/// are shadowsocks AEAD streams, so this presents a single `AsyncRead+AsyncWrite`.
#[pin_project(project = RealmProxyStreamProj)]
pub enum RealmProxyStream {
    /// ss over a QUIC bidi stream.
    Quic(#[pin] ProxyClientStream<RealmStream>),
    /// ss over a direct TCP connection (PATH B).
    Tcp(#[pin] ProxyClientStream<TcpStream>),
}

impl RealmProxyStream {
    /// `true` if this stream uses the direct-TCP path (PATH B) instead of QUIC.
    pub fn is_direct_tcp(&self) -> bool {
        matches!(self, RealmProxyStream::Tcp(_))
    }
}

impl AsyncRead for RealmProxyStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            RealmProxyStreamProj::Quic(s) => s.poll_read(cx, buf),
            RealmProxyStreamProj::Tcp(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RealmProxyStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            RealmProxyStreamProj::Quic(s) => s.poll_write(cx, buf),
            RealmProxyStreamProj::Tcp(s) => s.poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            RealmProxyStreamProj::Quic(s) => s.poll_flush(cx),
            RealmProxyStreamProj::Tcp(s) => s.poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            RealmProxyStreamProj::Quic(s) => s.poll_shutdown(cx),
            RealmProxyStreamProj::Tcp(s) => s.poll_shutdown(cx),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            RealmProxyStreamProj::Quic(s) => s.poll_write_vectored(cx, bufs),
            RealmProxyStreamProj::Tcp(s) => s.poll_write_vectored(cx, bufs),
        }
    }
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
    /// Run the full client dance and hold the resulting carrier. When
    /// `prefer_tcp` is set, a background task watches the control stream for a
    /// direct-TCP endpoint offer (PATH B) and upgrades new connections to it.
    pub async fn connect(
        context: SharedContext,
        svr_cfg: ServerConfig,
        params: ClientParams,
        prefer_tcp: bool,
    ) -> io::Result<Self> {
        let carrier = client_connect(params).await.map_err(io::Error::other)?;
        let me = Self {
            context,
            svr_cfg,
            carrier,
            path_manager: Arc::new(PathManager::new(prefer_tcp)),
        };
        if prefer_tcp {
            me.spawn_control_loop();
        }
        Ok(me)
    }

    /// Open a proxied ss stream to `target`, choosing the best available path:
    /// direct TCP (PATH B) once offered and adopted, otherwise the QUIC carrier
    /// (PATH A). A TCP dial failure demotes the path and falls back to QUIC.
    pub async fn connect_target<A>(&self, target: A) -> io::Result<RealmProxyStream>
    where
        A: Into<Address>,
    {
        let target = target.into();
        if let Path::Tcp(addr) = self.path_manager.select() {
            match self.dial_tcp(addr, target.clone()).await {
                Ok(s) => return Ok(RealmProxyStream::Tcp(s)),
                Err(e) => {
                    log::debug!("realm: direct-TCP dial to {addr} failed ({e}); falling back to QUIC");
                    self.path_manager.mark_tcp_down();
                }
            }
        }
        let s = open_proxied(self.context.clone(), &self.carrier, &self.svr_cfg, target).await?;
        Ok(RealmProxyStream::Quic(s))
    }

    /// Dial the direct-TCP endpoint and present the session token (as the first
    /// bytes of the ss payload, under AEAD) so the server binds this connection
    /// to the authenticated session.
    async fn dial_tcp(
        &self,
        addr: SocketAddr,
        target: Address,
    ) -> io::Result<ProxyClientStream<TcpStream>> {
        let token = self
            .path_manager
            .tcp_token()
            .ok_or_else(|| io::Error::other("no direct-TCP session token"))?;
        let tcp = TcpStream::connect(addr).await?;
        let mut stream = ProxyClientStream::from_stream(self.context.clone(), tcp, &self.svr_cfg, target);
        stream.write_all(&token).await?;
        Ok(stream)
    }

    /// Background control-stream consumer: adopt direct-TCP offers, answer pings.
    fn spawn_control_loop(&self) {
        let conn = self.carrier.connection().clone();
        let pm = self.path_manager.clone();
        tokio::spawn(async move {
            // The server opens the control stream; accept it.
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(v) => v,
                Err(_) => return,
            };
            loop {
                match control::read_msg(&mut recv).await {
                    Ok(ControlMsg::TcpEndpointOffer { addresses, token }) => {
                        let addr = addresses.iter().find_map(|s| s.parse::<SocketAddr>().ok());
                        if let Some(addr) = addr {
                            pm.set_tcp(addr, token);
                            log::info!(
                                "realm: direct-TCP path (PATH B) offered at {addr}; new connections will use it"
                            );
                            let _ = control::write_msg(&mut send, &ControlMsg::TcpEndpointAck { accepted: true }).await;
                        } else {
                            let _ = control::write_msg(&mut send, &ControlMsg::TcpEndpointAck { accepted: false }).await;
                        }
                    }
                    Ok(ControlMsg::TcpPathDown) => pm.mark_tcp_down(),
                    Ok(ControlMsg::Ping(ts)) => {
                        let _ = control::write_msg(&mut send, &ControlMsg::Pong(ts)).await;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
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

    /// Wrap an already-established carrier (e.g. from [`RealmListener`], which
    /// accepts many clients concurrently).
    pub fn from_carrier(context: SharedContext, svr_cfg: ServerConfig, carrier: QuicCarrier) -> Self {
        Self { context, svr_cfg, carrier }
    }

    /// Serve proxied TCP streams **and** ss-UDP datagrams over the QUIC carrier
    /// (PATH A) until it closes.
    pub async fn serve(&self) -> io::Result<()> {
        tokio::select! {
            r = self.serve_quic_only() => r,
            r = serve_udp_relay(self.context.clone(), self.svr_cfg.clone(), self.carrier.connection().clone()) => r,
        }
    }

    /// QUIC accept loop: handshake each bidi stream, dial its target, relay.
    async fn serve_quic_only(&self) -> io::Result<()> {
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

    /// Serve with the direct-TCP path (PATH B) enabled: try to map an external
    /// TCP port via UPnP/NAT-PMP, announce it over the control stream, and accept
    /// token-bound native ss-TCP connections in parallel with the QUIC carrier.
    /// If mapping fails (no cooperating gateway), transparently stays on QUIC.
    pub async fn serve_with_upgrade(
        &self,
        methods: Vec<shadowsocks_realm::portmap::PortMapMethod>,
        external_port: u16,
        lease_secs: u32,
    ) -> io::Result<()> {
        use std::time::Duration;

        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let local = listener.local_addr()?;

        let mapped = shadowsocks_realm::portmap::map_tcp(
            &methods,
            local,
            external_port,
            lease_secs,
            Duration::from_secs(3),
        )
        .await;

        match mapped {
            Ok(active) => {
                let external = active.mapping().external;
                let token = shadowsocks_realm::random_token();
                log::info!(
                    "realm PATH B: mapped local {local} -> external {external}; offering direct TCP"
                );
                let res = self.serve_with_tcp_path(listener, external, token).await;
                let _ = active.release().await;
                res
            }
            Err(e) => {
                log::info!("realm PATH B: no port mapping available ({e}); staying on QUIC");
                self.serve_quic_only().await
            }
        }
    }

    /// PATH B core (also used directly by tests with an injected `external`
    /// address): offer the endpoint over the control stream, accept token-bound
    /// ss-TCP connections on `listener`, and run the QUIC carrier concurrently.
    pub async fn serve_with_tcp_path(
        &self,
        listener: tokio::net::TcpListener,
        external: SocketAddr,
        token: [u8; TOKEN_LEN],
    ) -> io::Result<()> {
        let method = self.svr_cfg.method();
        let conn = self.carrier.connection().clone();

        // Offer the TCP endpoint over a fresh control stream.
        let (mut csend, mut crecv) = conn.open_bi().await.map_err(io::Error::other)?;
        control::write_msg(
            &mut csend,
            &ControlMsg::TcpEndpointOffer {
                addresses: vec![external.to_string()],
                token,
            },
        )
        .await
        .map_err(io::Error::other)?;
        // Drain control replies (ack / ping) in the background.
        tokio::spawn(async move {
            loop {
                match control::read_msg(&mut crecv).await {
                    Ok(ControlMsg::Ping(ts)) => {
                        let _ = control::write_msg(&mut csend, &ControlMsg::Pong(ts)).await;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        // Token-bound native ss-TCP accept loop.
        let ctx = self.context.clone();
        let key = self.svr_cfg.key().to_vec();
        let tcp_task = tokio::spawn(async move {
            loop {
                let (tcp, _peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let ctx = ctx.clone();
                let key = key.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_tcp_conn(ctx, tcp, method, &key, &token).await {
                        log::debug!("realm PATH B tcp conn ended: {e}");
                    }
                });
            }
        });

        // Run the QUIC carrier (TCP streams + UDP datagrams) until it closes,
        // then stop the direct-TCP accept loop.
        let res = tokio::select! {
            r = self.serve_quic_only() => r,
            r = serve_udp_relay(self.context.clone(), self.svr_cfg.clone(), self.carrier.connection().clone()) => r,
        };
        tcp_task.abort();
        res
    }

    /// The established carrier.
    pub fn carrier(&self) -> &QuicCarrier {
        &self.carrier
    }
}

/// Direct-TCP (PATH B) options for [`RealmListener::run`].
#[derive(Debug, Clone)]
pub struct TcpUpgradeOpts {
    /// Port-mapping backends to try, in order.
    pub methods: Vec<shadowsocks_realm::portmap::PortMapMethod>,
    /// Requested external TCP port (`0` = router-chosen).
    pub external_port: u16,
    /// Mapping lease in seconds.
    pub lease_secs: u32,
}

/// Multi-client realm server: registers once and accepts **many** clients
/// concurrently, each on its own carrier (and its own per-client socket), so a
/// single `ssserver` realm entry serves many `sslocal`s at the same time.
pub struct RealmListener {
    context: SharedContext,
    svr_cfg: ServerConfig,
    registration: Arc<shadowsocks_realm::session::RealmServerRegistration>,
}

impl RealmListener {
    /// Register with the rendezvous (one registration, kept alive by heartbeat).
    pub async fn bind(
        context: SharedContext,
        svr_cfg: ServerConfig,
        params: ServerParams,
    ) -> io::Result<Self> {
        let registration = shadowsocks_realm::session::RealmServerRegistration::register(params)
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            context,
            svr_cfg,
            registration: Arc::new(registration),
        })
    }

    /// Accept clients forever. Each punch event is handled in its own task
    /// (punch + QUIC handshake + serve), so many clients connect concurrently
    /// without blocking each other. `tcp_upgrade` enables PATH B per client.
    pub async fn run(&self, tcp_upgrade: Option<TcpUpgradeOpts>) -> io::Result<()> {
        loop {
            let punch = match self.registration.next_punch().await {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("realm: rendezvous event error: {e}; retrying shortly");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            };

            let reg = self.registration.clone();
            let context = self.context.clone();
            let svr_cfg = self.svr_cfg.clone();
            let upgrade = tcp_upgrade.clone();
            tokio::spawn(async move {
                let carrier = match reg.handle_punch(punch).await {
                    Ok(c) => c,
                    Err(e) => {
                        log::debug!("realm: client handshake failed: {e}");
                        return;
                    }
                };
                log::info!("realm: new client carrier from {}", carrier.remote_address());
                let server = RealmServer::from_carrier(context, svr_cfg, carrier);
                let res = match upgrade {
                    Some(u) => server.serve_with_upgrade(u.methods, u.external_port, u.lease_secs).await,
                    None => server.serve().await,
                };
                if let Err(e) = res {
                    log::debug!("realm: client serve ended: {e}");
                }
            });
        }
    }
}

/// Handle one native ss-TCP (PATH B) connection: ss handshake → verify the
/// session token (ss-encrypted payload prefix) → relay to the target.
async fn serve_tcp_conn(
    context: SharedContext,
    tcp: TcpStream,
    method: CipherKind,
    key: &[u8],
    expected_token: &[u8; TOKEN_LEN],
) -> io::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut ss = ProxyServerStream::from_stream(context, tcp, method, key);
    let target = ss.handshake().await?;

    let mut token = [0u8; TOKEN_LEN];
    ss.read_exact(&mut token).await?;
    if &token != expected_token {
        return Err(io::Error::other("direct-TCP session token mismatch"));
    }

    let mut remote = TcpStream::connect(target.to_string()).await?;
    copy_encrypted_bidirectional(method, &mut ss, &mut remote).await?;
    Ok(())
}

// ===================== ss-UDP over QUIC datagrams =====================

/// A datagram transport backed by QUIC unreliable datagrams over the carrier.
/// Implements the shadowsocks `DatagramSend`/`DatagramReceive` traits so it can
/// drop into [`ProxySocket`] and reuse the existing ss-UDP AEAD codec unchanged.
#[derive(Debug)]
pub struct QuicDatagramSocket {
    conn: quinn::Connection,
    rx: std::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<bytes::Bytes>>,
}

impl QuicDatagramSocket {
    /// Wrap a carrier connection; a background task pumps inbound datagrams.
    pub fn new(conn: quinn::Connection) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let c = conn.clone();
        tokio::spawn(async move {
            while let Ok(b) = c.read_datagram().await {
                if tx.send(b).is_err() {
                    break;
                }
            }
        });
        Self {
            conn,
            rx: std::sync::Mutex::new(rx),
        }
    }
}

impl DatagramSocket for QuicDatagramSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0))
    }
}

impl DatagramSend for QuicDatagramSocket {
    fn poll_send(&self, _cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.conn.send_datagram(bytes::Bytes::copy_from_slice(buf)) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(io::Error::other(e))),
        }
    }
    fn poll_send_to(
        &self,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
        _target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.poll_send(cx, buf)
    }
    fn poll_send_ready(&self, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl DatagramReceive for QuicDatagramSocket {
    fn poll_recv(&self, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut rx = self.rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some(b)) => {
                let n = b.len().min(buf.remaining());
                buf.put_slice(&b[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "carrier closed")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_recv_from(
        &self,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        match self.poll_recv(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(self.conn.remote_address())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_recv_ready(&self, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Client-side ss-UDP socket over the carrier's QUIC datagrams. Use it exactly
/// like a normal ss `ProxySocket` (send/recv with target [`Address`]).
pub type RealmUdpClient = ProxySocket<QuicDatagramSocket>;

impl RealmClient {
    /// Build a ss-UDP `ProxySocket` over the carrier (for sslocal UDP associate).
    pub fn proxy_udp(&self) -> RealmUdpClient {
        let sock = QuicDatagramSocket::new(self.carrier.connection().clone());
        ProxySocket::from_socket(UdpSocketType::Client, self.context.clone(), &self.svr_cfg, sock)
    }
}

async fn resolve_target(addr: &Address) -> io::Result<SocketAddr> {
    match addr {
        Address::SocketAddress(sa) => Ok(*sa),
        Address::DomainNameAddress(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| io::Error::other(format!("cannot resolve {host}:{port}"))),
    }
}

/// Server-side ss-UDP relay over the carrier's QUIC datagrams: decrypt each
/// datagram into (target, payload), forward over a per-target UDP socket, and
/// return replies as datagrams. One association map per carrier.
async fn serve_udp_relay(
    context: SharedContext,
    svr_cfg: ServerConfig,
    conn: quinn::Connection,
) -> io::Result<()> {
    let proxy = Arc::new(ProxySocket::<QuicDatagramSocket>::from_socket(
        UdpSocketType::Server,
        context,
        &svr_cfg,
        QuicDatagramSocket::new(conn),
    ));
    let assoc: Arc<tokio::sync::Mutex<HashMap<String, Arc<tokio::net::UdpSocket>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, target, _pkt) = match proxy.recv(&mut buf).await {
            Ok(v) => v,
            Err(_) => return Ok(()), // carrier closed
        };
        let payload = buf[..n].to_vec();
        let key = target.to_string();

        let out = {
            let mut map = assoc.lock().await;
            if let Some(s) = map.get(&key) {
                s.clone()
            } else {
                let sa = match resolve_target(&target).await {
                    Ok(sa) => sa,
                    Err(e) => {
                        log::debug!("realm udp: resolve {key} failed: {e}");
                        continue;
                    }
                };
                let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                if s.connect(sa).await.is_err() {
                    continue;
                }
                let s = Arc::new(s);
                map.insert(key.clone(), s.clone());

                // reply pump: target -> client (re-encrypted as a datagram)
                let proxy2 = proxy.clone();
                let s2 = s.clone();
                let reply_addr = target.clone();
                tokio::spawn(async move {
                    let mut rbuf = vec![0u8; 64 * 1024];
                    loop {
                        match s2.recv(&mut rbuf).await {
                            Ok(rn) => {
                                if proxy2.send(&reply_addr, &rbuf[..rn]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
                s
            }
        };
        let _ = out.send(&payload).await;
    }
}
