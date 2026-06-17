# shadowsocks-realm

Protocol-agnostic **P2P UDP NAT-traversal** for shadowsocks, compatible with the
open-source [Hysteria Realms] rendezvous server (`hysteria-realm-server`). It lets
an `ssserver` behind NAT/CGNAT be reached by `sslocal` **without a public IP or
port forwarding**, while keeping the shadowsocks proxy protocol unchanged.

This crate has **no shadowsocks dependencies** — it is the reusable transport.
The shadowsocks AEAD layer rides on top via the `shadowsocks` crate's `realm`
module (feature `realm`).

## How it works

```
        rendezvous (Go, unmodified)  ── introductions only (HTTP + SSE) ──
                 ▲                                   ▲
   register/SSE  │ STUN                         STUN │ connect
                 │                                   │
        ssserver (behind NAT)                  sslocal (client)
                 └──── UDP hole punching (HYRLMv1 Hello/Ack) ────┘
                              │  punched direct UDP path  │
                              ▼                           ▼
   PATH A (immediate):  QUIC (quinn) over the punched socket
                        carries ss AEAD streams + ss-UDP datagrams
   PATH B (opportunistic): UPnP/NAT-PMP maps a direct TCP port; the server
                        announces it in-band over QUIC; new connections move to
                        native shadowsocks TCP. QUIC always backstops.
```

The output of a successful traversal is a single connected `QuicCarrier`; what
runs on top is the integrator's choice — here, shadowsocks.

## Modules

| Module | Purpose |
|---|---|
| `url` | `realm://token@host/realm[?stun=&lport=]` parsing |
| `rendezvous` | HTTP + SSE client for `hysteria-realm-server` (register / events / connect / connects / heartbeat / delete) |
| `stun` | RFC 5389 Binding discovery (`XOR-MAPPED-ADDRESS`), multi-server |
| `punch` | byte-exact `HYRLMv1` Hello/Ack codec + symmetric punch loop |
| `socket` | `PunchedSocket`: the connected UDP socket after a successful punch |
| `quic` | `quinn` carrier over the punched socket; self-signed + SHA-256-pin TLS |
| `tls` | self-signed cert generation + pinning verifier (ACME is roadmap) |
| `control` | in-band control protocol (TCP-endpoint offer/ack, ping/pong) over QUIC |
| `path_manager` | per-new-connection QUIC↔TCP selection |
| `portmap` | best-effort UPnP-IGD / NAT-PMP external TCP port mapping (PATH B) |
| `session` | `client_connect` / `server_accept`: the full dance, returning a `QuicCarrier` |

## Wire compatibility

The rendezvous and punch wire formats match `apernet/hysteria` exactly, so these
nodes work with the **stock** `hysteria-realm-server`. The punch codec is
unit-tested byte-for-byte against the reference (`testing/nat-sim/hyrlm.py`):
salt(8) ‖ XOR(payload, `SHA256(obfsKey ‖ salt)`), payload = `"HYRLMv1\0"`(8) ‖
type(1) ‖ nonce(16) ‖ padding(0..1024). We do **not** interoperate with Hysteria
*proxy* nodes — the payload over the path is shadowsocks.

## Testing

```bash
# Unit + integration tests (spawn the Python testbed mocks on loopback)
cargo test -p shadowsocks-realm

# Full shadowsocks-over-realm end-to-end (rendezvous + STUN + punch + QUIC + ss)
cargo test -p shadowsocks --features realm --test realm_e2e

# The original double-NAT testbed (proves the punch through real double-NAT)
cd testing/nat-sim
unshare -Urnm --map-root-user env -u http_proxy -u https_proxy -u all_proxy bash punch_demo.sh
```

[Hysteria Realms]: https://v2.hysteria.network/docs/advanced/Realms/
