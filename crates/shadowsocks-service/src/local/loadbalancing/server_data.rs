//! Identifier of server

use std::{
    fmt::{self, Debug},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use shadowsocks::{ServerConfig, net::ConnectOpts};
use tokio::sync::Mutex;

use crate::{config::ServerInstanceConfig, local::context::ServiceContext};

use super::server_stat::{Score, ServerStat, ServerStatData};

/// Server's statistic score
pub struct ServerScore {
    stat_data: Mutex<ServerStat>,
    score: AtomicU32,
}

impl ServerScore {
    /// Create a `ServerScore`
    pub fn new(user_weight: f32, max_server_rtt: Duration, check_window: Duration) -> Self {
        let max_server_rtt = max_server_rtt.as_millis() as u32;
        assert!(max_server_rtt > 0);

        Self {
            stat_data: Mutex::new(ServerStat::new(user_weight, max_server_rtt, check_window)),
            score: AtomicU32::new(u32::MAX),
        }
    }

    /// Get server's current statistic scores
    pub fn score(&self) -> u32 {
        self.score.load(Ordering::Acquire)
    }

    /// Append a `Score` into statistic and recalculate score of the server
    pub async fn push_score(&self, score: Score) -> u32 {
        let updated_score = {
            let mut stat = self.stat_data.lock().await;
            stat.push_score(score)
        };
        self.score.store(updated_score, Ordering::Release);
        updated_score
    }

    /// Append a `Score` into statistic and recalculate score of the server
    pub async fn push_score_fetch_statistic(&self, score: Score) -> (u32, ServerStatData) {
        let (updated_score, data) = {
            let mut stat = self.stat_data.lock().await;
            (stat.push_score(score), *stat.data())
        };
        self.score.store(updated_score, Ordering::Release);
        (updated_score, data)
    }

    /// Report request failure of this server, which will eventually records an `Errored` score
    pub async fn report_failure(&self) -> u32 {
        self.push_score(Score::Errored).await
    }

    /// Get statistic data
    pub async fn stat_data(&self) -> ServerStatData {
        *self.stat_data.lock().await.data()
    }
}

impl Debug for ServerScore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerScore").field("score", &self.score()).finish()
    }
}

/// Identifier for a server
pub struct ServerIdent {
    tcp_score: ServerScore,
    udp_score: ServerScore,
    svr_cfg: ServerInstanceConfig,
    connect_opts: ConnectOpts,
    /// Lazily-established realm transport carrier (feature `realm`).
    #[cfg(feature = "realm")]
    realm_client: Mutex<Option<Arc<shadowsocks::realm::RealmClient>>>,
}

impl Debug for ServerIdent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerIdent")
            .field("tcp_score", &self.tcp_score)
            .field("udp_score", &self.udp_score)
            .field("svr_cfg", &self.svr_cfg)
            .field("connect_opts", &self.connect_opts)
            .finish()
    }
}

impl ServerIdent {
    /// Create a `ServerIdent`
    pub fn new(
        context: Arc<ServiceContext>,
        svr_cfg: ServerInstanceConfig,
        max_server_rtt: Duration,
        check_window: Duration,
    ) -> Self {
        let mut connect_opts = context.connect_opts_ref().clone();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(fwmark) = svr_cfg.outbound_fwmark {
            connect_opts.fwmark = Some(fwmark);
        }

        #[cfg(target_os = "freebsd")]
        if let Some(user_cookie) = svr_cfg.outbound_user_cookie {
            connect_opts.user_cookie = Some(user_cookie);
        }

        if let Some(bind_local_addr) = svr_cfg.outbound_bind_addr {
            connect_opts.bind_local_addr = Some(SocketAddr::new(bind_local_addr, 0));
        }

        if let Some(ref bind_interface) = svr_cfg.outbound_bind_interface {
            connect_opts.bind_interface = Some(bind_interface.clone());
        }

        Self {
            tcp_score: ServerScore::new(svr_cfg.config.weight().tcp_weight(), max_server_rtt, check_window),
            udp_score: ServerScore::new(svr_cfg.config.weight().udp_weight(), max_server_rtt, check_window),
            svr_cfg,
            connect_opts,
            #[cfg(feature = "realm")]
            realm_client: Mutex::new(None),
        }
    }

    pub fn connect_opts_ref(&self) -> &ConnectOpts {
        &self.connect_opts
    }

    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg.config
    }

    pub fn server_config_mut(&mut self) -> &mut ServerConfig {
        &mut self.svr_cfg.config
    }

    pub fn server_instance_config(&self) -> &ServerInstanceConfig {
        &self.svr_cfg
    }

    pub fn tcp_score(&self) -> &ServerScore {
        &self.tcp_score
    }

    pub fn udp_score(&self) -> &ServerScore {
        &self.udp_score
    }

    /// The realm transport config for this server, if it uses realm transport.
    #[cfg(feature = "realm")]
    pub fn realm_config(&self) -> Option<&crate::config::RealmConfig> {
        self.svr_cfg.realm.as_ref()
    }

    /// Get (establishing on first use) the realm transport carrier for this
    /// server. On failure the cache is left empty so a later call retries.
    #[cfg(feature = "realm")]
    pub async fn realm_client(
        &self,
        context: shadowsocks::context::SharedContext,
    ) -> std::io::Result<Arc<shadowsocks::realm::RealmClient>> {
        use shadowsocks::realm::shadowsocks_realm::quic::ClientTls;
        use shadowsocks::realm::shadowsocks_realm::session::ClientParams;

        let mut guard = self.realm_client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }

        let realm_cfg = self
            .svr_cfg
            .realm
            .as_ref()
            .ok_or_else(|| std::io::Error::other("server is not configured for realm transport"))?;

        // Pin takes precedence; otherwise honour `insecure`; otherwise error.
        let tls = match (realm_cfg.pin_sha256.as_deref(), realm_cfg.insecure) {
            (Some(pin), _) => ClientTls::Pin(parse_pin_sha256(Some(pin))?),
            (None, true) => ClientTls::Insecure,
            (None, false) => {
                return Err(std::io::Error::other(
                    "realm client requires quic_tls.pin_sha256 (64 hex) or quic_tls.insecure = true",
                ));
            }
        };
        let params = ClientParams {
            rendezvous: realm_cfg.rendezvous.clone(),
            stun_servers: realm_cfg.stun_servers.clone(),
            tls,
            rendezvous_insecure: realm_cfg.insecure,
            lport: realm_cfg.lport,
            punch_deadline: Duration::from_secs(10),
        };

        let client = shadowsocks::realm::RealmClient::connect(
            context,
            self.svr_cfg.config.clone(),
            params,
            realm_cfg.prefer_tcp,
        )
        .await?;
        let client = Arc::new(client);
        *guard = Some(client.clone());
        Ok(client)
    }

    /// Drop the cached realm carrier (e.g. after a dial failure), so the next
    /// request re-establishes it.
    #[cfg(feature = "realm")]
    pub async fn reset_realm_client(&self) {
        *self.realm_client.lock().await = None;
    }
}

/// Parse a 64-char hex SHA-256 certificate pin into bytes.
#[cfg(feature = "realm")]
fn parse_pin_sha256(pin: Option<&str>) -> std::io::Result<[u8; 32]> {
    let pin = pin
        .ok_or_else(|| std::io::Error::other("realm client requires quic_tls.pin_sha256"))?
        .trim();
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(std::io::Error::other(
            "quic_tls.pin_sha256 must be 64 hex characters (SHA-256 of the server cert)",
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&pin[i * 2..i * 2 + 2], 16)
            .map_err(|e| std::io::Error::other(format!("invalid pin_sha256: {e}")))?;
    }
    Ok(out)
}
