//! TLS for the QUIC carrier (Phase 4): self-signed certificate generation and a
//! SHA-256 certificate-pinning verifier.
//!
//! The default, zero-config mode is a self-signed certificate whose SHA-256
//! fingerprint is pinned by the client (the server announces / the operator
//! copies the pin out of band). ACME / real certificates (Phase 9) reuse the
//! same `rustls` configs produced here.

use std::sync::{Arc, Once};

use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// ALPN protocol identifier negotiated on the QUIC carrier.
pub const ALPN: &[u8] = b"ss-realm/1";

/// Install the aws-lc-rs crypto provider as the process default (idempotent).
fn ensure_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn default_provider() -> Arc<CryptoProvider> {
    ensure_provider();
    CryptoProvider::get_default()
        .expect("crypto provider installed")
        .clone()
}

/// Generate a self-signed certificate and private key for the given subject
/// alternative names (e.g. `["realm"]`).
pub fn generate_self_signed(
    subject_alt_names: Vec<String>,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let certified = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| Error::Rendezvous(format!("self-signed cert: {e}")))?;
    let cert = certified.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    Ok((cert, PrivateKeyDer::Pkcs8(key)))
}

/// SHA-256 fingerprint of a DER certificate — the value pinned by clients.
pub fn cert_sha256(cert: &CertificateDer<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cert.as_ref());
    h.finalize().into()
}

/// Build a `rustls::ServerConfig` presenting `cert`/`key`, with our ALPN.
pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    ensure_provider();
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| Error::Rendezvous(format!("server tls config: {e}")))?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(cfg)
}

/// Build a `rustls::ClientConfig` that accepts exactly the certificate whose
/// SHA-256 fingerprint equals `pin`, with our ALPN.
pub fn client_config_pinned(pin: [u8; 32]) -> Result<rustls::ClientConfig> {
    let provider = default_provider();
    let verifier = Arc::new(PinnedVerifier { pin, provider });
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(cfg)
}

/// Build a `rustls::ClientConfig` that accepts **any** server certificate
/// (the carrier's `insecure` mode). The shadowsocks AEAD layer remains the real
/// end-to-end authentication, so the QUIC carrier TLS here only provides
/// transport encryption — matching Hysteria's `insecure: true`.
pub fn client_config_insecure() -> Result<rustls::ClientConfig> {
    let provider = default_provider();
    let verifier = Arc::new(InsecureVerifier { provider });
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(cfg)
}

/// A `ServerCertVerifier` that accepts a single pinned certificate (by SHA-256)
/// while still cryptographically verifying the handshake signatures, so the peer
/// must actually possess the pinned certificate's private key.
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

/// A `ServerCertVerifier` that accepts any certificate chain (used for the
/// carrier's `insecure` mode). Handshake signatures are still verified against
/// the presented certificate's key.
#[derive(Debug)]
struct InsecureVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if cert_sha256(end_entity) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_and_pin_roundtrip() {
        let (cert, _key) = generate_self_signed(vec!["realm".into()]).unwrap();
        let pin = cert_sha256(&cert);
        // building a pinned client config with that pin succeeds
        let _client = client_config_pinned(pin).unwrap();
    }
}
