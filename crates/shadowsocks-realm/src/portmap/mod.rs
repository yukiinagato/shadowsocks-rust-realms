//! Best-effort external TCP port mapping for the direct-TCP path (PATH B, Phase 5).
//!
//! Two backends are attempted in order; both are strictly best-effort, since the
//! QUIC path (PATH A) always backstops connectivity:
//! * [`upnp`]   — UPnP-IGD via `igd-next`.
//! * [`natpmp`] — NAT-PMP / PCP, for routers that prefer it (e.g. Apple).
//!
//! A failed mapping is never fatal: callers treat [`map_tcp`] returning `Err` as
//! "no direct-TCP path available" and stay on QUIC.

pub mod natpmp;
pub mod upnp;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::error::{Error, Result};

/// A successful external port mapping: the public `ip:port` reachable from the
/// internet, plus the local port it forwards to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapping {
    /// Public address the router forwards (announced to the peer over QUIC).
    pub external: SocketAddr,
    /// Local TCP port the mapping forwards to.
    pub internal_port: u16,
}

/// Which port-mapping backend to try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMapMethod {
    /// UPnP Internet Gateway Device protocol.
    Upnp,
    /// NAT-PMP / PCP.
    NatPmp,
}

/// An active mapping created by [`map_tcp`]; release it on shutdown.
pub enum ActiveMapping {
    /// A UPnP-IGD mapping (carries the gateway handle for removal).
    Upnp(upnp::UpnpMapping),
    /// A NAT-PMP mapping (re-requested with lease 0 to release).
    NatPmp {
        /// The gateway that granted the mapping.
        gateway: Ipv4Addr,
        /// The local port that was mapped.
        internal_port: u16,
        /// The resulting public mapping.
        mapping: PortMapping,
    },
}

impl ActiveMapping {
    /// The public mapping, regardless of backend.
    pub fn mapping(&self) -> PortMapping {
        match self {
            ActiveMapping::Upnp(m) => m.mapping(),
            ActiveMapping::NatPmp { mapping, .. } => *mapping,
        }
    }

    /// Release the mapping (best-effort).
    pub async fn release(self) -> Result<()> {
        match self {
            ActiveMapping::Upnp(m) => m.release().await,
            ActiveMapping::NatPmp { gateway, internal_port, .. } => natpmp::map_tcp(
                gateway,
                internal_port,
                0,
                0,
                Duration::from_millis(500),
                3,
            )
            .await
            .map(|_| ()),
        }
    }
}

/// Attempt to map an external TCP port for `internal_addr`, trying each method
/// in order and returning the first success. Best-effort: `Err` means PATH B is
/// unavailable and the caller should remain on the QUIC path.
pub async fn map_tcp(
    methods: &[PortMapMethod],
    internal_addr: SocketAddr,
    requested_external_port: u16,
    lease_secs: u32,
    search_timeout: Duration,
) -> Result<ActiveMapping> {
    for method in methods {
        match method {
            PortMapMethod::Upnp => {
                if let Ok(m) = upnp::map_tcp(
                    internal_addr,
                    requested_external_port,
                    lease_secs,
                    search_timeout,
                )
                .await
                {
                    return Ok(ActiveMapping::Upnp(m));
                }
            }
            PortMapMethod::NatPmp => {
                if let Some(gateway) = guess_gateway_v4()
                    && let Ok(mapping) = natpmp::map_tcp(
                        gateway,
                        internal_addr.port(),
                        requested_external_port,
                        lease_secs,
                        Duration::from_millis(700),
                        3,
                    )
                    .await
                {
                    return Ok(ActiveMapping::NatPmp {
                        gateway,
                        internal_port: internal_addr.port(),
                        mapping,
                    });
                }
            }
        }
    }
    Err(Error::PortMap("no port-mapping method succeeded".into()))
}

/// Best-effort guess of the IPv4 default gateway: open a UDP socket "toward" a
/// public address (no packets sent) to learn our LAN IP, then assume the gateway
/// is `<net>.1`. Works on typical home networks; returns `None` otherwise.
fn guess_gateway_v4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && v4.octets()[0] != 0 => {
            let o = v4.octets();
            Some(Ipv4Addr::new(o[0], o[1], o[2], 1))
        }
        _ => None,
    }
}
