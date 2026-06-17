//! QUIC carrier over a [`PunchedSocket`] (PATH A, Phase 4).
//!
//! Once a hole is punched, we run `quinn` directly over the same UDP socket
//! (reusing the punched local port) so traffic flows immediately. One peer takes
//! the QUIC **server** role, the other the **client** role; thereafter both have
//! a full duplex [`quinn::Connection`] offering reliable bidi streams (one per
//! proxied TCP connection) and unreliable datagrams (for proxied UDP).
//!
//! TLS is the self-signed + SHA-256-pin scheme from [`crate::tls`].

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{Error, Result};
use crate::socket::PunchedSocket;
use crate::tls;

/// Server name presented in the client's TLS SNI. The pinning verifier ignores
/// the name (it matches on the certificate fingerprint), but quinn requires a
/// syntactically valid one.
const SERVER_NAME: &str = "realm";

/// An established QUIC carrier: the live connection plus the endpoint that owns
/// the punched socket (kept alive for the connection's lifetime).
#[derive(Debug)]
pub struct QuicCarrier {
    endpoint: Endpoint,
    connection: Connection,
}

impl QuicCarrier {
    /// The live QUIC connection (open streams / send datagrams on this).
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The underlying endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The peer's address.
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Close the connection gracefully and wait for the endpoint to drain.
    pub async fn close(&self) {
        self.connection.close(0u32.into(), b"bye");
        self.endpoint.wait_idle().await;
    }
}

fn endpoint_from_punched(
    punched: PunchedSocket,
    server_config: Option<ServerConfig>,
) -> Result<(Endpoint, SocketAddr)> {
    let (tokio_sock, peer) = punched.into_parts();
    let std_sock = tokio_sock.into_std()?;
    std_sock.set_nonblocking(true)?;
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        server_config,
        std_sock,
        Arc::new(TokioRuntime),
    )
    .map_err(Error::Io)?;
    Ok((endpoint, peer))
}

/// Take the **client** role over a punched socket, verifying the server's
/// certificate against `pin` (its SHA-256 fingerprint).
pub async fn connect_client(punched: PunchedSocket, pin: [u8; 32]) -> Result<QuicCarrier> {
    let (mut endpoint, peer) = endpoint_from_punched(punched, None)?;

    let crypto = tls::client_config_pinned(pin)?;
    let qcc = QuicClientConfig::try_from(crypto)
        .map_err(|e| Error::Rendezvous(format!("quic client config: {e}")))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(qcc)));

    let connecting = endpoint
        .connect(peer, SERVER_NAME)
        .map_err(|e| Error::Rendezvous(format!("quic connect: {e}")))?;
    let connection = connecting
        .await
        .map_err(|e| Error::Rendezvous(format!("quic handshake: {e}")))?;
    Ok(QuicCarrier { endpoint, connection })
}

/// Take the **server** role over a punched socket, presenting `cert`/`key`.
pub async fn accept_server(
    punched: PunchedSocket,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<QuicCarrier> {
    let crypto = tls::server_config(cert, key)?;
    let qsc = QuicServerConfig::try_from(crypto)
        .map_err(|e| Error::Rendezvous(format!("quic server config: {e}")))?;
    let server_config = ServerConfig::with_crypto(Arc::new(qsc));

    let (endpoint, _peer) = endpoint_from_punched(punched, Some(server_config))?;
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| Error::Rendezvous("endpoint closed before a connection arrived".into()))?;
    let connection = incoming
        .await
        .map_err(|e| Error::Rendezvous(format!("quic server handshake: {e}")))?;
    Ok(QuicCarrier { endpoint, connection })
}
