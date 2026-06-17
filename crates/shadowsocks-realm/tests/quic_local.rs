//! Phase 4 integration test: punch two local UDP sockets, run the QUIC carrier
//! over them (one server, one client), and echo both a bidi stream and a
//! datagram P2P over the punched path.

use std::time::Duration;

use tokio::net::UdpSocket;

use shadowsocks_realm::quic;
use shadowsocks_realm::socket::PunchedSocket;
use shadowsocks_realm::tls;

#[tokio::test]
async fn quic_stream_and_datagram_over_punched_path() {
    // Punch two local sockets toward each other.
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();
    let nonce = [3u8; 16];
    let obfs = [9u8; 32];

    let ta = tokio::spawn(async move {
        PunchedSocket::connect(a, &[b_addr], &nonce, &obfs, Duration::from_secs(5))
            .await
            .expect("A punch")
    });
    let tb = tokio::spawn(async move {
        PunchedSocket::connect(b, &[a_addr], &nonce, &obfs, Duration::from_secs(5))
            .await
            .expect("B punch")
    });
    let punched_client = ta.await.unwrap(); // A = QUIC client
    let punched_server = tb.await.unwrap(); // B = QUIC server

    // Self-signed cert for the server; client pins its fingerprint.
    let (cert, key) = tls::generate_self_signed(vec!["realm".into()]).unwrap();
    let pin = tls::cert_sha256(&cert);

    // Server: accept, echo one bidi stream and one datagram.
    let server = tokio::spawn(async move {
        let carrier = quic::accept_server(punched_server, cert, key)
            .await
            .expect("server carrier");
        let conn = carrier.connection().clone();

        // Echo a datagram.
        let dg = conn.read_datagram().await.expect("read datagram");
        conn.send_datagram(dg).expect("send datagram back");

        // Echo a bidi stream.
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        let mut buf = vec![0u8; 1024];
        let n = recv.read(&mut buf).await.expect("read").unwrap_or(0);
        send.write_all(&buf[..n]).await.expect("write echo");
        send.finish().expect("finish");

        // Keep the carrier alive until the client is done.
        tokio::time::sleep(Duration::from_millis(500)).await;
        carrier.close().await;
    });

    // Client: connect, exercise datagram + stream.
    let carrier = quic::connect_client(punched_client, pin)
        .await
        .expect("client carrier");
    let conn = carrier.connection();

    conn.send_datagram(bytes::Bytes::from_static(b"dgram-ping"))
        .expect("send datagram");
    let echoed = conn.read_datagram().await.expect("read datagram echo");
    assert_eq!(&echoed[..], b"dgram-ping");

    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"stream-hello").await.expect("write");
    send.finish().expect("finish");
    let mut got = Vec::new();
    recv.read_to_end(64).await.map(|v| got = v).expect("read_to_end");
    assert_eq!(got, b"stream-hello");

    carrier.close().await;
    server.await.unwrap();
}
