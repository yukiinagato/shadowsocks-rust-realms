//! Phase 5 test: in an environment with no UPnP-IGD / NAT-PMP gateway (like CI
//! or this sandbox), `map_tcp` must fail gracefully and promptly rather than
//! hang or panic — PATH B is best-effort and QUIC backstops it.

use std::time::{Duration, Instant};

use shadowsocks_realm::portmap::{self, PortMapMethod};

#[tokio::test]
async fn map_tcp_is_graceful_noop_without_gateway() {
    let internal = "127.0.0.1:8388".parse().unwrap();
    let start = Instant::now();

    let result = portmap::map_tcp(
        &[PortMapMethod::Upnp, PortMapMethod::NatPmp],
        internal,
        0,
        7200,
        Duration::from_secs(2), // short UPnP search timeout
    )
    .await;

    // No gateway here, so this must be an Err (not a panic, not a hang).
    assert!(result.is_err(), "expected best-effort failure without a gateway");
    // And it must return reasonably quickly.
    assert!(
        start.elapsed() < Duration::from_secs(12),
        "port mapping took too long: {:?}",
        start.elapsed()
    );
}
