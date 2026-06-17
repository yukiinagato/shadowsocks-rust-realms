//! Phase 1 integration test: drive the rendezvous client through the full
//! register / events / connect / connects handshake against the testbed mock
//! `testing/nat-sim/rendezvous.py` (a faithful subset of `hysteria-realm-server`).
//!
//! Skips gracefully (test passes) if `python3` or the mock script is unavailable,
//! so `cargo test` stays green in minimal environments.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use shadowsocks_realm::RealmUrl;
use shadowsocks_realm::rendezvous::client::RendezvousClient;
use shadowsocks_realm::rendezvous::events::RendezvousEvent;
use shadowsocks_realm::rendezvous::types::ConnectBody;

/// Kill the spawned mock server when the guard drops.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn mock_script() -> Option<PathBuf> {
    // crates/shadowsocks-realm -> repo root -> testing/nat-sim/rendezvous.py
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/nat-sim/rendezvous.py");
    p.canonicalize().ok()
}

fn python3() -> Option<String> {
    for cand in ["python3", "python"] {
        if Command::new(cand).arg("--version").output().is_ok() {
            return Some(cand.to_string());
        }
    }
    None
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn rendezvous_full_handshake() {
    let (Some(py), Some(script)) = (python3(), mock_script()) else {
        eprintln!("skipping: python3 or rendezvous.py not available");
        return;
    };

    let port = free_port();
    let child = Command::new(&py)
        .arg(&script)
        .arg("127.0.0.1")
        .arg(port.to_string())
        .current_dir(script.parent().unwrap())
        .spawn()
        .expect("spawn rendezvous mock");
    let _guard = ChildGuard(child);

    // Wait for the mock to accept connections.
    let mut ready = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "mock rendezvous did not start");

    let url = RealmUrl::parse(&format!("realm+http://test-token@127.0.0.1:{port}/room-1")).unwrap();

    let server = RendezvousClient::new(url.clone()).unwrap();
    let client = RendezvousClient::new(url).unwrap();

    let reg = server
        .register(vec!["10.0.0.1:1111".into()])
        .await
        .expect("register");
    assert!(reg.ttl > 0);
    let sid = reg.session_id.clone();

    // Server side: wait for the punch event, then post fresh addresses.
    let srv = tokio::spawn(async move {
        loop {
            match server.poll_event(&sid).await.expect("poll_event") {
                RendezvousEvent::Punch(cb) => {
                    server
                        .post_connects(&sid, &cb.nonce, vec!["10.0.0.2:2222".into()])
                        .await
                        .expect("post_connects");
                    return cb;
                }
                RendezvousEvent::HeartbeatAck => continue,
            }
        }
    });

    // Let the server reach its events long-poll first.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let nonce = "00112233445566778899aabbccddeeff".to_string();
    let obfs = "f".repeat(64);
    let peer = client
        .connect(&ConnectBody {
            addresses: vec!["10.0.0.3:3333".into()],
            nonce: nonce.clone(),
            obfs: obfs.clone(),
        })
        .await
        .expect("connect");

    // Client receives the addresses the server posted via /connects.
    assert_eq!(peer.addresses, vec!["10.0.0.2:2222".to_string()]);
    assert_eq!(peer.nonce, nonce);

    // Server received the client's connect body.
    let got = srv.await.unwrap();
    assert_eq!(got.addresses, vec!["10.0.0.3:3333".to_string()]);
    assert_eq!(got.nonce, nonce);
    assert_eq!(got.obfs, obfs);
}
