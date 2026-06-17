//! Phase 6 integration test: over a real punched QUIC path, the server opens a
//! control stream and offers a TCP endpoint; the client adopts it via its
//! PathManager (QUIC → TCP) and acks; then a TcpPathDown demotes back to QUIC.

use std::time::Duration;

use tokio::net::UdpSocket;

use shadowsocks_realm::control::{self, ControlMsg, TOKEN_LEN};
use shadowsocks_realm::path_manager::{Path, PathManager};
use shadowsocks_realm::socket::PunchedSocket;
use shadowsocks_realm::{quic, tls};

#[tokio::test]
async fn control_stream_drives_path_upgrade_and_fallback() {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();
    let nonce = [11u8; 16];
    let obfs = [22u8; 32];

    let ta = tokio::spawn(async move {
        PunchedSocket::connect(a, &[b_addr], &nonce, &obfs, Duration::from_secs(5))
            .await
            .unwrap()
    });
    let tb = tokio::spawn(async move {
        PunchedSocket::connect(b, &[a_addr], &nonce, &obfs, Duration::from_secs(5))
            .await
            .unwrap()
    });
    let client_sock = ta.await.unwrap();
    let server_sock = tb.await.unwrap();

    let (cert, key) = tls::generate_self_signed(vec!["realm".into()]).unwrap();
    let pin = tls::cert_sha256(&cert);

    let offered_token = [0x5Au8; TOKEN_LEN];
    let offered_addr = "203.0.113.7:9000";

    // Server: open a control stream, offer a TCP endpoint, read the ack, then
    // later signal the path is down.
    let server = tokio::spawn(async move {
        let carrier = quic::accept_server(server_sock, cert, key).await.unwrap();
        let conn = carrier.connection().clone();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        control::write_msg(
            &mut send,
            &ControlMsg::TcpEndpointOffer {
                addresses: vec![offered_addr.to_string()],
                token: offered_token,
            },
        )
        .await
        .unwrap();

        let ack = control::read_msg(&mut recv).await.unwrap();
        assert_eq!(ack, ControlMsg::TcpEndpointAck { accepted: true });

        control::write_msg(&mut send, &ControlMsg::TcpPathDown).await.unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;
        carrier.close().await;
    });

    // Client: accept the control stream, drive the PathManager.
    let carrier = quic::connect_client(client_sock, quic::ClientTls::Pin(pin)).await.unwrap();
    let conn = carrier.connection().clone();
    let pm = PathManager::new(true);

    assert_eq!(pm.select(), Path::Quic); // starts on QUIC

    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    match control::read_msg(&mut recv).await.unwrap() {
        ControlMsg::TcpEndpointOffer { addresses, token } => {
            // In production the client would dial+verify ss AEAD here first.
            let addr = addresses[0].parse().unwrap();
            pm.set_tcp(addr, token);
            control::write_msg(&mut send, &ControlMsg::TcpEndpointAck { accepted: true })
                .await
                .unwrap();
        }
        other => panic!("expected offer, got {other:?}"),
    }

    // After adoption, new connections prefer TCP.
    assert_eq!(pm.select(), Path::Tcp(offered_addr.parse().unwrap()));
    assert_eq!(pm.tcp_token(), Some(offered_token));

    // Server signals the TCP path is down → demote to QUIC.
    match control::read_msg(&mut recv).await.unwrap() {
        ControlMsg::TcpPathDown => pm.mark_tcp_down(),
        other => panic!("expected path-down, got {other:?}"),
    }
    assert_eq!(pm.select(), Path::Quic);

    carrier.close().await;
    server.await.unwrap();
}
