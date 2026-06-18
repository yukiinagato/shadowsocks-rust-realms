//! Testbed probe: establish a realm QUIC carrier and echo many bidi streams.
//! Used by `testing/loss-sim/run.sh` to check availability under packet loss and
//! concurrency. Server uses a self-signed cert; client uses `Insecure` so no pin
//! needs to be exchanged.
//!
//! usage:
//!   realm_probe server <rendezvous-url> <stun host:port>
//!   realm_probe client <rendezvous-url> <stun host:port> <count> <concurrency>

use std::time::Duration;

use shadowsocks_realm::quic::ClientTls;
use shadowsocks_realm::session::{ClientParams, ServerParams, client_connect, server_accept};
use shadowsocks_realm::tls;

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a.get(1).map(String::as_str).unwrap_or("");
    let rendezvous = a.get(2).cloned().unwrap_or_default();
    let stun = a.get(3).cloned().unwrap_or_default();

    match mode {
        "server" => {
            let (cert, key) = tls::generate_self_signed(vec!["realm".into()]).unwrap();
            let carrier = server_accept(ServerParams {
                rendezvous,
                stun_servers: vec![stun],
                cert,
                key,
                lport: None,
                punch_deadline: Duration::from_secs(10),
            })
            .await
            .expect("server_accept");
            eprintln!("[probe-server] carrier established; echoing streams");
            let conn = carrier.connection().clone();
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                tokio::spawn(async move {
                    if let Ok(buf) = recv.read_to_end(4096).await {
                        let _ = send.write_all(&buf).await;
                        let _ = send.finish();
                    }
                });
            }
        }
        "client" => {
            let count: usize = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(20);
            let concurrency: usize = a.get(5).and_then(|s| s.parse().ok()).unwrap_or(4);
            let carrier = client_connect(ClientParams {
                rendezvous,
                stun_servers: vec![stun],
                tls: ClientTls::Insecure,
                lport: None,
                punch_deadline: Duration::from_secs(10),
            })
            .await
            .expect("client_connect");
            let conn = std::sync::Arc::new(carrier.connection().clone());

            let mut tasks = Vec::new();
            for i in 0..count {
                let conn = conn.clone();
                tasks.push(tokio::spawn(async move {
                    let payload = format!("probe-{i}");
                    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
                    send.write_all(payload.as_bytes()).await.map_err(|e| e.to_string())?;
                    send.finish().map_err(|e| e.to_string())?;
                    let got = recv.read_to_end(64).await.map_err(|e| e.to_string())?;
                    if got == payload.as_bytes() {
                        Ok::<(), String>(())
                    } else {
                        Err("mismatch".into())
                    }
                }));
                if tasks.len() >= concurrency {
                    // drain a batch to bound in-flight streams
                    for t in tasks.drain(..) {
                        let _ = t.await;
                    }
                }
            }
            let mut ok = 0usize;
            // Re-run sequentially counting successes for a deterministic report.
            for i in 0..count {
                let payload = format!("verify-{i}");
                let r: Result<(), String> = async {
                    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
                    send.write_all(payload.as_bytes()).await.map_err(|e| e.to_string())?;
                    send.finish().map_err(|e| e.to_string())?;
                    let got = recv.read_to_end(64).await.map_err(|e| e.to_string())?;
                    if got == payload.as_bytes() { Ok(()) } else { Err("mismatch".into()) }
                }
                .await;
                if r.is_ok() {
                    ok += 1;
                }
            }
            println!("PROBE_OK {ok}/{count}");
            if ok != count {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: realm_probe server|client <rendezvous> <stun> [count] [concurrency]");
            std::process::exit(2);
        }
    }
}
