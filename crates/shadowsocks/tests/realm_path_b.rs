//! PATH B end-to-end test (feature `realm`): over a real punched QUIC carrier,
//! the server announces a direct-TCP endpoint over the control stream; the
//! client adopts it and routes a new proxied connection over **native ss-TCP**
//! (token-bound), not QUIC. The TCP "external" address is injected (the same
//! loopback listener) so the data path is exercised without a real router —
//! real UPnP/NAT-PMP mapping is covered separately by the NAT-PMP testbed.
//!
//! Skips gracefully if python3 / the testbed mocks are unavailable.

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

use shadowsocks_realm::random_token;
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
async fn path_b_routes_new_connection_over_direct_tcp() {
    let (Some(py), Some(dir)) = (python3(), nat_sim_dir()) else {
        eprintln!("skipping: python3 or testing/nat-sim not available");
        return;
    };

    let rzv_port = free_tcp_port();
    let stun_port = free_tcp_port();
    let _rzv = ChildGuard(spawn_py(&py, &dir, "rendezvous.py", "127.0.0.1", rzv_port));
    let _stun = ChildGuard(spawn_py(&py, &dir, "stun_server.py", "127.0.0.1", stun_port));

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

    // Target echo server.
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

    let method = CipherKind::AES_256_GCM;
    const PASS: &str = "path-b-pass";
    let (cert, key) = tls::generate_self_signed(vec!["realm".into()]).unwrap();
    let pin = tls::cert_sha256(&cert);
    let rendezvous = format!("realm+http://test-token@127.0.0.1:{rzv_port}/room-pathb");
    let stun_servers = vec![format!("127.0.0.1:{stun_port}")];
    let token = random_token();

    // --- Server: accept carrier, then PATH B with an injected loopback endpoint.
    let srv_rendezvous = rendezvous.clone();
    let srv_stun = stun_servers.clone();
    let server = tokio::spawn(async move {
        let ctx = Context::new_shared(ServerType::Server);
        let svr_cfg = ServerConfig::new(("127.0.0.1".to_string(), 8388u16), PASS, method).unwrap();
        let server = RealmServer::accept(
            ctx,
            svr_cfg,
            ServerParams {
                rendezvous: srv_rendezvous,
                stun_servers: srv_stun,
                cert,
                key,
                rendezvous_insecure: false,
                lport: None,
                punch_deadline: Duration::from_secs(8),
            },
        )
        .await
        .expect("server accept");

        // The direct-TCP listener; its loopback address is reachable by the
        // client, so we offer it directly (stands in for a UPnP-mapped port).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let external = listener.local_addr().unwrap();
        let _ = server.serve_with_tcp_path(listener, external, token).await;
    });

    tokio::time::sleep(Duration::from_millis(400)).await;

    // --- Client: connect with prefer_tcp so the control loop adopts PATH B.
    let ctx = Context::new_shared(ServerType::Local);
    let svr_cfg = ServerConfig::new(("127.0.0.1".to_string(), 8388u16), PASS, method).unwrap();
    let client = tokio::time::timeout(
        Duration::from_secs(12),
        RealmClient::connect(
            ctx,
            svr_cfg,
            ClientParams {
                rendezvous,
                stun_servers,
                tls: shadowsocks_realm::quic::ClientTls::Pin(pin),
                rendezvous_insecure: false,
                lport: None,
                punch_deadline: Duration::from_secs(8),
            },
            true, // prefer_tcp
        ),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect");

    // Wait for the TCP endpoint offer to be received and adopted.
    let mut adopted = false;
    for _ in 0..50 {
        if client.path_manager().tcp_available() {
            adopted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(adopted, "client did not adopt the direct-TCP path");

    // A new connection must now go over direct TCP (PATH B), not QUIC.
    let mut cs = client
        .connect_target(shadowsocks::relay::Address::from(echo_addr))
        .await
        .expect("connect_target");
    assert!(cs.is_direct_tcp(), "new connection should use direct TCP (PATH B)");

    let payload = b"hello over PATH B direct tcp";
    cs.write_all(payload).await.expect("write");
    cs.flush().await.expect("flush");
    cs.shutdown().await.expect("shutdown");

    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), cs.read_to_end(&mut got))
        .await
        .expect("read timed out")
        .expect("read_to_end");
    assert_eq!(got, payload, "PATH B round-trip payload mismatch");

    client.close().await;
    server.abort();
}
