//! Phase 2 integration test: discover a UDP socket's reflexive address against
//! the testbed STUN responder `testing/nat-sim/stun_server.py`.
//!
//! Skips gracefully if `python3` or the script is unavailable.

use std::net::UdpSocket as StdUdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use tokio::net::UdpSocket;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn script() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/nat-sim/stun_server.py")
        .canonicalize()
        .ok()
}

fn python3() -> Option<String> {
    for cand in ["python3", "python"] {
        if Command::new(cand).arg("--version").output().is_ok() {
            return Some(cand.to_string());
        }
    }
    None
}

fn free_udp_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn stun_discovers_local_reflexive_address() {
    let (Some(py), Some(script)) = (python3(), script()) else {
        eprintln!("skipping: python3 or stun_server.py not available");
        return;
    };

    let stun_port = free_udp_port();
    let child = Command::new(&py)
        .arg(&script)
        .arg("127.0.0.1")
        .arg(stun_port.to_string())
        .current_dir(script.parent().unwrap())
        .spawn()
        .expect("spawn stun mock");
    let _guard = ChildGuard(child);

    // The UDP responder has no TCP port to poll; give it a moment to bind.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_port = sock.local_addr().unwrap().port();
    let server = format!("127.0.0.1:{stun_port}").parse().unwrap();

    let reflexive = shadowsocks_realm::stun::discover(&sock, server, 5, Duration::from_secs(1))
        .await
        .expect("stun discovery");

    // The responder echoes the source as seen on the wire: 127.0.0.1:<our port>.
    assert_eq!(reflexive.ip().to_string(), "127.0.0.1");
    assert_eq!(reflexive.port(), local_port);
}
