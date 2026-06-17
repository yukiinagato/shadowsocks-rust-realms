//! Phase 8 end-to-end test (feature `realm`): a real shadowsocks AEAD proxy
//! session carried over the **full** realm stack — rendezvous + STUN + HYRLMv1
//! punch + QUIC carrier — exercised on loopback against the testbed mocks
//! (`rendezvous.py`, `stun_server.py`).
//!
//! Flow proven:
//!   sslocal-side `ProxyClientStream`  ─ss AEAD→  QUIC bidi  ─→  punched UDP path
//!     →  ssserver-side `ProxyServerStream` (handshake) → TCP to target echo
//!   and the echoed bytes return all the way back, decrypted, to the client.
//!
//! Skips gracefully if `python3` / the mock scripts are unavailable.

#![cfg(feature = "realm")]

use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::realm::{RealmClient, RealmServer};

use shadowsocks_realm::session::{ClientParams, ServerParams};
use shadowsocks_realm::tls;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn nat_sim_dir() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/nat-sim")
        .canonicalize()
        .ok()
}

fn python3() -> Option<String> {
    for c in ["python3", "python"] {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

fn free_tcp_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn spawn_py(py: &str, dir: &PathBuf, script: &str, ip: &str, port: u16) -> Child {
    Command::new(py)
        .arg(dir.join(script))
        .arg(ip)
        .arg(port.to_string())
        .current_dir(dir)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {script}: {e}"))
}

#[tokio::test]
async fn shadowsocks_over_full_realm_stack() {
    let (Some(py), Some(dir)) = (python3(), nat_sim_dir()) else {
        eprintln!("skipping: python3 or testing/nat-sim not available");
        return;
    };

    // --- Mocks: rendezvous (TCP) + STUN (UDP) ---
    let rzv_port = free_tcp_port();
    let stun_port = free_tcp_port(); // reuse a free number for the UDP bind
    let _rzv = ChildGuard(spawn_py(&py, &dir, "rendezvous.py", "127.0.0.1", rzv_port));
    let _stun = ChildGuard(spawn_py(&py, &dir, "stun_server.py", "127.0.0.1", stun_port));

    // Wait for the rendezvous TCP port; give the UDP STUN responder a moment too.
    let mut ready = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", rzv_port)).is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "rendezvous mock did not start");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Target echo server ---
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match echo.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    // --- Shared shadowsocks server config (same key both ends) ---
    let method = CipherKind::AES_256_GCM;
    const SS_PASSWORD: &str = "realm-e2e-pass";

    // --- Carrier TLS: server holds cert/key, client pins it ---
    let (cert, key) = tls::generate_self_signed(vec!["realm".into()]).unwrap();
    let pin = tls::cert_sha256(&cert);

    let rendezvous = format!("realm+http://test-token@127.0.0.1:{rzv_port}/room-e2e");
    let stun_servers = vec![format!("127.0.0.1:{stun_port}")];

    // --- Server side ---
    let srv_rendezvous = rendezvous.clone();
    let srv_stun = stun_servers.clone();
    let server = tokio::spawn(async move {
        let ctx = Context::new_shared(ServerType::Server);
        let svr_cfg =
            ServerConfig::new(("127.0.0.1".to_string(), 8388u16), SS_PASSWORD, method).unwrap();
        let server = RealmServer::accept(
            ctx,
            svr_cfg,
            ServerParams {
                rendezvous: srv_rendezvous,
                stun_servers: srv_stun,
                cert,
                key,
                lport: None,
                punch_deadline: Duration::from_secs(8),
            },
        )
        .await
        .expect("RealmServer::accept");
        let _ = server.serve().await;
    });

    // Let the server register + reach its events long-poll.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // --- Client side ---
    let ctx = Context::new_shared(ServerType::Local);
    let svr_cfg =
        ServerConfig::new(("127.0.0.1".to_string(), 8388u16), SS_PASSWORD, method).unwrap();
    let client = tokio::time::timeout(
        Duration::from_secs(12),
        RealmClient::connect(
            ctx,
            svr_cfg,
            ClientParams {
                rendezvous,
                stun_servers,
                tls: shadowsocks_realm::quic::ClientTls::Pin(pin),
                lport: None,
                punch_deadline: Duration::from_secs(8),
            },
            true,
        ),
    )
    .await
    .expect("RealmClient::connect timed out")
    .expect("RealmClient::connect");

    // Open a proxied stream to the echo target and round-trip a payload.
    let mut cs = client
        .connect_target(shadowsocks::relay::Address::from(echo_addr))
        .await
        .expect("connect_target");

    let payload = b"hello over the realm stack!";
    cs.write_all(payload).await.expect("write");
    cs.flush().await.expect("flush");
    cs.shutdown().await.expect("shutdown"); // signal EOF so the echo closes

    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), cs.read_to_end(&mut got))
        .await
        .expect("read timed out")
        .expect("read_to_end");

    assert_eq!(got, payload, "round-trip payload mismatch");

    client.close().await;
    server.abort();
}
