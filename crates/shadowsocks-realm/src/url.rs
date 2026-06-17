//! Parsing for `realm://token@host[:port]/realm-name[?stun=...&lport=...]` URLs.
//!
//! Two schemes are accepted, matching Hysteria's conventions:
//!
//! * `realm://`      — rendezvous reached over HTTPS (default).
//! * `realm+http://` — rendezvous reached over plain HTTP (testing / self-host).
//!
//! Optional query parameters:
//!
//! * `stun=host:port` — may repeat; additional STUN servers to query.
//! * `lport=NNNN`     — bind the local UDP socket to this fixed port.

use crate::error::{Error, Result};

/// A parsed rendezvous locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmUrl {
    /// Bearer token presented to the rendezvous server.
    pub token: String,
    /// Rendezvous authority, `host` or `host:port` (no scheme).
    pub host: String,
    /// The realm (room) name — the path segment after the host.
    pub realm: String,
    /// `true` when the rendezvous is reached over HTTPS (scheme `realm://`),
    /// `false` for `realm+http://`.
    pub https: bool,
    /// Extra STUN servers from `?stun=` query parameters.
    pub stun_servers: Vec<String>,
    /// Optional fixed local UDP port from `?lport=`.
    pub lport: Option<u16>,
}

impl RealmUrl {
    /// Parse a `realm://` / `realm+http://` URL.
    pub fn parse(input: &str) -> Result<Self> {
        let bad = |m: &str| Error::InvalidUrl(format!("{m}: {input:?}"));

        let (https, rest) = if let Some(r) = input.strip_prefix("realm://") {
            (true, r)
        } else if let Some(r) = input.strip_prefix("realm+http://") {
            (false, r)
        } else {
            return Err(bad("expected scheme realm:// or realm+http://"));
        };

        // Split off the query string, if any.
        let (authority_path, query) = match rest.split_once('?') {
            Some((ap, q)) => (ap, Some(q)),
            None => (rest, None),
        };

        // userinfo (token) @ host / path
        let (token, host_path) = authority_path
            .split_once('@')
            .ok_or_else(|| bad("missing token@ before host"))?;
        if token.is_empty() {
            return Err(bad("empty token"));
        }

        let (host, realm) = host_path
            .split_once('/')
            .ok_or_else(|| bad("missing /realm-name path"))?;
        if host.is_empty() {
            return Err(bad("empty host"));
        }
        if realm.is_empty() {
            return Err(bad("empty realm name"));
        }

        let mut stun_servers = Vec::new();
        let mut lport = None;
        if let Some(q) = query {
            for pair in q.split('&').filter(|s| !s.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                match k {
                    "stun" => stun_servers.push(v.to_string()),
                    "lport" => {
                        lport = Some(
                            v.parse::<u16>()
                                .map_err(|_| bad("lport must be a u16"))?,
                        );
                    }
                    _ => {} // ignore unknown params for forward-compat
                }
            }
        }

        Ok(RealmUrl {
            token: token.to_string(),
            host: host.to_string(),
            realm: realm.to_string(),
            https,
            stun_servers,
            lport,
        })
    }

    /// Base rendezvous URL (scheme + authority) for HTTP requests, e.g.
    /// `https://realm.example.com`.
    pub fn base_http_url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}", self.host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_url() {
        let u = RealmUrl::parse(
            "realm://sekret@realm.example.com:8443/my-cabin-1f3a?stun=stun.l.google.com:19302&lport=51820",
        )
        .unwrap();
        assert_eq!(u.token, "sekret");
        assert_eq!(u.host, "realm.example.com:8443");
        assert_eq!(u.realm, "my-cabin-1f3a");
        assert!(u.https);
        assert_eq!(u.stun_servers, vec!["stun.l.google.com:19302"]);
        assert_eq!(u.lport, Some(51820));
        assert_eq!(u.base_http_url(), "https://realm.example.com:8443");
    }

    #[test]
    fn parses_plain_http_scheme() {
        let u = RealmUrl::parse("realm+http://tok@127.0.0.1:8080/room").unwrap();
        assert!(!u.https);
        assert_eq!(u.base_http_url(), "http://127.0.0.1:8080");
    }

    #[test]
    fn rejects_bad_inputs() {
        assert!(RealmUrl::parse("https://x@y/z").is_err());
        assert!(RealmUrl::parse("realm://noatsign/room").is_err());
        assert!(RealmUrl::parse("realm://tok@host").is_err());
        assert!(RealmUrl::parse("realm://@host/room").is_err());
    }
}
