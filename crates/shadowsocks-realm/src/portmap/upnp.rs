//! UPnP-IGD external TCP port mapping via `igd-next` (Phase 5).

use std::net::SocketAddr;
use std::time::Duration;

use igd_next::SearchOptions;
use igd_next::aio::Gateway;
use igd_next::aio::tokio::{Tokio, search_gateway};
use igd_next::PortMappingProtocol;

use super::PortMapping;
use crate::error::{Error, Result};

const DESCRIPTION: &str = "shadowsocks-realm";

/// An active UPnP-IGD TCP port mapping. Call [`UpnpMapping::release`] to remove
/// it from the gateway when the realm shuts down.
pub struct UpnpMapping {
    gateway: Gateway<Tokio>,
    external_port: u16,
    mapping: PortMapping,
}

impl UpnpMapping {
    /// The public address the gateway forwards to our local port.
    pub fn mapping(&self) -> PortMapping {
        self.mapping
    }

    /// Remove the mapping from the gateway.
    pub async fn release(self) -> Result<()> {
        self.gateway
            .remove_port(PortMappingProtocol::TCP, self.external_port)
            .await
            .map_err(|e| Error::PortMap(format!("remove_port: {e}")))
    }
}

/// Discover an IGD gateway and map `internal_addr`'s port (TCP) to an external
/// port. A `requested_external_port` of 0 reuses the internal port number.
pub async fn map_tcp(
    internal_addr: SocketAddr,
    requested_external_port: u16,
    lease_secs: u32,
    search_timeout: Duration,
) -> Result<UpnpMapping> {
    let opts = SearchOptions {
        timeout: Some(search_timeout),
        ..Default::default()
    };
    let gateway = search_gateway(opts)
        .await
        .map_err(|e| Error::PortMap(format!("no IGD gateway: {e}")))?;

    let external_ip = gateway
        .get_external_ip()
        .await
        .map_err(|e| Error::PortMap(format!("get_external_ip: {e}")))?;

    let external_port = if requested_external_port == 0 {
        internal_addr.port()
    } else {
        requested_external_port
    };

    gateway
        .add_port(
            PortMappingProtocol::TCP,
            external_port,
            internal_addr,
            lease_secs,
            DESCRIPTION,
        )
        .await
        .map_err(|e| Error::PortMap(format!("add_port: {e}")))?;

    Ok(UpnpMapping {
        gateway,
        external_port,
        mapping: PortMapping {
            external: SocketAddr::new(external_ip, external_port),
            internal_port: internal_addr.port(),
        },
    })
}
