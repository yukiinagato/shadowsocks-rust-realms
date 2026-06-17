//! Phase 3 integration test: two local UDP sockets perform the symmetric
//! HYRLMv1 punch toward each other, then exchange application data over the
//! resulting path (no NAT, but the full Hello/Ack handshake runs).

use std::time::Duration;

use tokio::net::UdpSocket;

use shadowsocks_realm::socket::PunchedSocket;

async fn recv_until_prefix(ps: &PunchedSocket, prefix: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 2048];
    for _ in 0..200 {
        let (n, _src) =
            tokio::time::timeout(Duration::from_secs(2), ps.recv_from(&mut buf))
                .await
                .expect("recv timed out")
                .expect("recv error");
        if buf[..n].starts_with(prefix) {
            return buf[..n].to_vec();
        }
        // otherwise it's a trailing punch Ack; keep reading
    }
    panic!("did not receive expected data prefix");
}

#[tokio::test]
async fn two_sockets_punch_and_exchange_data() {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();

    let nonce = [7u8; 16];
    let obfs = [42u8; 32];

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

    let pa = ta.await.unwrap();
    let pb = tb.await.unwrap();

    assert_eq!(pa.peer(), b_addr);
    assert_eq!(pb.peer(), a_addr);

    // Application round-trip over the punched path.
    pa.send(b"PING-from-A").await.unwrap();
    let got = recv_until_prefix(&pb, b"PING-from-A").await;
    assert_eq!(got, b"PING-from-A");

    pb.send(b"PONG-from-B").await.unwrap();
    let got = recv_until_prefix(&pa, b"PONG-from-B").await;
    assert_eq!(got, b"PONG-from-B");
}
