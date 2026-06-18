//! ss-UDP over QUIC datagrams e2e (feature `realm`): a client sends a proxied
//! UDP packet over the carrier's QUIC datagrams; the server decrypts it, relays
//! to a real UDP echo target, and the reply comes back — all reusing the stock
//! shadowsocks UDP AEAD codec via `ProxySocket`.
//!
//! Skips gracefully if python3 / the testbed mocks are unavailable.

#![cfg(feature = "realm")]

use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use tokio::net::UdpSocket;

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::realm::{RealmClient, RealmServer};
use shadowsocks::relay::Address;

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
async fn ss_udp_over_quic_datagrams() {
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

    // UDP echo target.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match echo.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let _ = echo.send_to(&buf[..n], from).await;
                }
                Err(_) => break,
            }
        }
    });

    let method = CipherKind::AES_256_GCM;
    const PASS: &str = "udp-pass";
    let (cert, key) = tls::generate_self_signed(vec!["realm".into()]).unwrap();
    let pin = tls::cert_sha256(&cert);
    let rendezvous = format!("realm+http://test-token@127.0.0.1:{rzv_port}/room-udp");
    let stun_servers = vec![format!("127.0.0.1:{stun_port}")];

    // Server.
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
        let _ = server.serve().await;
    });

    tokio::time::sleep(Duration::from_millis(400)).await;

    // Client.
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
            false,
        ),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect");

    let udp = client.proxy_udp();
    let target = Address::from(echo_addr);

    // Round-trip a couple of UDP packets.
    for i in 0..3u8 {
        let payload = format!("udp-datagram-{i}");
        udp.send(&target, payload.as_bytes()).await.expect("udp send");
        let mut buf = vec![0u8; 65536];
        let (n, _addr, _pkt) = tokio::time::timeout(Duration::from_secs(5), udp.recv(&mut buf))
            .await
            .expect("udp recv timed out")
            .expect("udp recv");
        assert_eq!(&buf[..n], payload.as_bytes(), "udp echo mismatch");
    }

    client.close().await;
    server.abort();
}
