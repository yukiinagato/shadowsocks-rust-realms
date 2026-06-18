//! Multi-client / concurrency e2e (feature `realm`): one `RealmListener`
//! (ssserver-side) serves several independent clients at the same time, each on
//! its own punched carrier, all proxying through the same rendezvous. Verifies
//! the per-client-socket model and that streams stay isolated under concurrency.
//!
//! Skips gracefully if python3 / the testbed mocks are unavailable.

#![cfg(feature = "realm")]

use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::realm::{RealmClient, RealmListener};

use shadowsocks_realm::session::{ClientParams, ServerParams};
use shadowsocks_realm::tls;

const NUM_CLIENTS: usize = 4;
const PASS: &str = "multiclient-pass";

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_clients_concurrently() {
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

    // Echo target.
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
    let (cert, key) = tls::generate_self_signed(vec!["realm".into()]).unwrap();
    let pin = tls::cert_sha256(&cert);
    let rendezvous = format!("realm+http://test-token@127.0.0.1:{rzv_port}/room-multi");
    let stun_servers = vec![format!("127.0.0.1:{stun_port}")];

    // Server: one RealmListener serving all clients.
    let srv_rendezvous = rendezvous.clone();
    let srv_stun = stun_servers.clone();
    let server = tokio::spawn(async move {
        let ctx = Context::new_shared(ServerType::Server);
        let svr_cfg = ServerConfig::new(("127.0.0.1".to_string(), 8388u16), PASS, method).unwrap();
        let listener = RealmListener::bind(
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
        .expect("listener bind");
        let _ = listener.run(None).await;
    });

    tokio::time::sleep(Duration::from_millis(400)).await;

    // Launch NUM_CLIENTS concurrently; each proxies a unique payload.
    let rendezvous = Arc::new(rendezvous);
    let stun_servers = Arc::new(stun_servers);
    let mut tasks = Vec::new();
    for i in 0..NUM_CLIENTS {
        let rendezvous = rendezvous.clone();
        let stun_servers = stun_servers.clone();
        tasks.push(tokio::spawn(async move {
            let ctx = Context::new_shared(ServerType::Local);
            let svr_cfg =
                ServerConfig::new(("127.0.0.1".to_string(), 8388u16), PASS, method).unwrap();
            let client = tokio::time::timeout(
                Duration::from_secs(15),
                RealmClient::connect(
                    ctx,
                    svr_cfg,
                    ClientParams {
                        rendezvous: (*rendezvous).clone(),
                        stun_servers: (*stun_servers).clone(),
                        tls: shadowsocks_realm::quic::ClientTls::Pin(pin),
                        rendezvous_insecure: false,
                        lport: None,
                        punch_deadline: Duration::from_secs(8),
                    },
                    false,
                ),
            )
            .await
            .map_err(|_| "connect timeout")?
            .map_err(|e| format!("connect: {e}"))?;

            let mut cs = client
                .connect_target(shadowsocks::relay::Address::from(echo_addr))
                .await
                .map_err(|e| format!("connect_target: {e}"))?;

            let payload = format!("client-{i}-payload-{}", "x".repeat(64));
            cs.write_all(payload.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
            cs.flush().await.ok();
            cs.shutdown().await.ok();

            let mut got = Vec::new();
            tokio::time::timeout(Duration::from_secs(6), cs.read_to_end(&mut got))
                .await
                .map_err(|_| "read timeout")?
                .map_err(|e| format!("read: {e}"))?;

            client.close().await;
            if got == payload.as_bytes() {
                Ok::<usize, String>(i)
            } else {
                Err(format!("client {i} payload mismatch"))
            }
        }));
    }

    let mut ok = 0usize;
    for t in tasks {
        match t.await.expect("client task panicked") {
            Ok(_) => ok += 1,
            Err(e) => panic!("a client failed: {e}"),
        }
    }
    assert_eq!(ok, NUM_CLIENTS, "all clients must succeed concurrently");

    server.abort();
}
