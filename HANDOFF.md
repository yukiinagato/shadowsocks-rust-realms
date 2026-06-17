# Project handoff — shadowsocks-rust-realms

Read this first when resuming in a new session. It captures decisions, what's
done, what's blocked, and the exact next action.

## Goal

Adapt **Hysteria Realms** (P2P UDP hole-punching: rendezvous + STUN + UDP hole
punch) onto shadowsocks, so an `ssserver` behind NAT/CGNAT is reachable by
`sslocal` **without a public IP or port forwarding**, keeping the shadowsocks
proxy protocol unchanged. Both client and server roles.

## Decisions locked in (from the user)

1. **Transport = dual-path.** After the hole is punched: run **QUIC (quinn)
   immediately** over the punched UDP socket so traffic flows at once; in the
   background try **UPnP / NAT-PMP** to map a direct TCP port; when TCP becomes
   available, **seamlessly upgrade** to native shadowsocks TCP. The TCP endpoint
   is announced **in-band over the existing QUIC connection** (so the stock Go
   rendezvous never needs to know about TCP). Seamless switch is **per-new-
   connection** by default; true mid-flow migration is optional (roadmap
   Phase 10).
2. **TLS** for the QUIC carrier: self-signed + SHA-256 pin (default) **and**
   ACME/real-cert (DNS-01) support.
3. **Rendezvous**: compatibility only — the user self-hosts the stock Go
   `hysteria-realm-server`. No rendezvous server code in this repo.
4. **Feature flag** `realm`: off by default, opt-in only via `--features realm`
   (NOT in `full`/`full-extra` — keeps the heavy dep tree out of the project's
   default MSRV/clippy/release CI; realm has its own `.github/workflows/realm.yml`).
5. Delivery style: **plan first, then implement phase by phase**, each phase
   ending compiling + tested. The user wants the final result tested for real
   connectivity in a simulated NAT environment **before** delivery.

## Status

| Item | State |
|---|---|
| `DESIGN.md` (architecture + 10-phase roadmap) | ✅ done (v2, dual-path) |
| `testing/nat-sim/` double-NAT testbed | ✅ done & validated |
| Core mechanism proven through real double-NAT (STUN, rendezvous, HYRLMv1 punch, data) | ✅ 3/3 green |
| **Phase 0 — Scaffolding & deps** | ✅ done |
| **Phase 1 — Rendezvous client** | ✅ done — unit + live-mock handshake |
| **Phase 2 — STUN discovery** | ✅ done — byte-exact oracle vector + live mock |
| **Phase 3 — Punch codec + loop** | ✅ done — byte-exact encode/decode vs `hyrlm.py` + two-socket punch |
| **Phase 4 — QUIC carrier** | ✅ done — stream+datagram echo over punched path |
| **Phase 5 — UPnP/NAT-PMP** | ✅ done — codec unit tests + graceful no-op |
| **Phase 6 — Control + PathManager** | ✅ done — live QUIC upgrade/fallback |
| **Phases 7–8 — shadowsocks wiring + e2e** | ✅ **complete** — real `sslocal`/`ssserver` binaries proxy over realm; `curl` through SOCKS5 → QUIC(punched) → ssserver → target verified. |
| **Binary wiring** (config + sslocal dial + ssserver accept) | ✅ done, see below |
| **GitHub CI** (`.github/workflows/realm.yml`) | ✅ done |
| Phase 9 (ACME/hardening), Phase 10 (mid-stream migration) | ⬜ not started |

**Test totals (all green):** `shadowsocks-realm` 23 unit + 6 integration; `shadowsocks-service` 3 realm config-parse tests; `shadowsocks` realm e2e 1; **binary e2e** (real `sslocal`+`ssserver`+`curl`) 1; double-NAT testbed 3/3. Clippy `-D warnings` clean. Default (no-realm) build intact; whole workspace + binaries build with `--features realm`.

### Binary wiring (done)

- **Config** (`crates/shadowsocks-service/src/config.rs`): `realm` block on the
  single-server `SSConfig` and the array `SSServerExtConfig`; typed
  `pub realm: Option<RealmConfig>` on `ServerInstanceConfig`; parse + serialize
  wired both ways; 3 parse unit tests. Schema: `configs/realm/{server,client}.json5`.
  (Client config note: `server` must be a valid non-unspecified placeholder —
  realm reaches the server via rendezvous, not that address.)
- **ssserver** (`server/mod.rs`): `run_realm_server` accept loop (register →
  accept punched QUIC carrier → `RealmServer::serve` → re-register), spawned when
  an entry has a realm config; logs the self-signed cert pin for the client.
- **sslocal** (`loadbalancing/server_data.rs` + `local/net/tcp/auto_proxy_stream.rs`):
  `ServerIdent` lazily establishes/caches a `RealmClient`; `AutoProxyClientStream`
  has a `Realm(ProxyClientStream<RealmStream>)` variant; the dial path routes realm
  servers over the QUIC carrier. (Single realm server ⇒ balancer skips active
  probing, so no spurious TCP checks to the NAT'd address.)
- **Binary e2e**: `testing/realm-e2e/run_binary_e2e.sh` (also a CI step).

### Remaining (not blocking a working single-client deployment)

1. **Multi-client** — `session::server_accept` serves one client per registered
   socket (punch then QUIC on the same socket). Many concurrent distinct clients
   need a custom `AsyncUdpSocket` that demuxes punch vs QUIC on a shared socket
   (DESIGN §5). One carrier already multiplexes all of one client's connections.
2. **ss-UDP over QUIC datagrams**; **PATH B** end-to-end (announce mapped TCP over
   the control stream + token-bound TCP accept; client switch via `PathManager`).
3. **Phase 9**: DNS-01 ACME for the carrier, reconnect/heartbeat resilience,
   metrics, ACL/outbound-proxy on the realm server path (currently dials targets
   directly).

### Blocker — RESOLVED

The toolchain network restriction has been lifted. `static.rust-lang.org`,
`sh.rustup.rs`, and `index/static.crates.io` are now reachable **directly (no
proxy needed)**. Rust **1.96.0 stable** (aarch64) is installed via rustup at
`$HOME/.cargo` / `$HOME/.rustup`. Satisfies the repo's edition-2024 / 1.91 MSRV.

### Sandbox build recipe (IMPORTANT — needed every session)

Each `bash` tool call is independent (no env/cwd carryover, backgrounded procs
are killed between calls). To build, export these every call:

```bash
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export CMAKE_POLICY_VERSION_MINIMUM=3.5      # cmake 4.x dropped pre-3.5 compat; aws-lc-sys needs this
export CARGO_TARGET_DIR="$HOME/rtarget"      # MUST be off the mount — the mounted
                                             # repo dir disallows the file-removes
                                             # cargo does (os error 1, "Operation not permitted")
cd /sessions/<session>/mnt/shadowsocks-rust-realms
```

- `cmake` was installed via `pip install cmake --break-system-packages` (lands in
  `$HOME/.local/bin`). `cc`/`gcc`/`make`/`perl` are present; `clang`/`go`/`nasm`
  are NOT (aarch64 aws-lc-sys ships pregenerated bindings, so libclang isn't
  needed).
- A clean build of `shadowsocks-realm`'s dep tree (aws-lc-sys C build, ring,
  quinn, rustls, reqwest, igd-next) takes a few minutes. The 45 s per-call cap is
  fine: just re-run `cargo build` — cargo's incremental cache resumes. Compiled
  crates persist in `$HOME/rtarget`.

### Phase 0 result (what landed)

- New crate `crates/shadowsocks-realm` (edition 2024, zero shadowsocks deps).
  Modules scaffolded with docs + core types: `error`, `url` (fully implemented +
  tested), `stun`, `punch`, `socket`, `rendezvous/{mod,client,events,types}`,
  `portmap/{mod,upnp,natpmp}`.
- Deps added & confirmed building under 1.96: `quinn 0.11.9`, `rustls 0.23`,
  `rcgen 0.14`, `reqwest 0.13` (features `rustls,rustls-native-certs,webpki-roots,
  stream,json,http2` — note 0.13 renamed `rustls-tls`→`rustls`), `igd-next 0.17`
  (`aio_tokio`), `sha2 0.11`, `tokio`, `tokio-util`, `bytes`, `hex`, `rand 0.10`,
  `futures`, `serde`/`serde_json`.
- Feature wiring: root `realm = ["shadowsocks-service/realm"]` (opt-in only, NOT
  in `full-extra`); `shadowsocks-service` `realm = ["shadowsocks/realm"]`;
  `shadowsocks` `realm = ["dep:shadowsocks-realm"]`. Verified: `--features realm`
  pulls the crate in through the whole chain; **absent from default builds**.
- Verify commands run green: `cargo build -p shadowsocks-realm` (0 warnings),
  `cargo test -p shadowsocks-realm` (3 passed), `cargo check -p shadowsocks
  --features realm`.

## What's already validated (and reusable as a test oracle)

`testing/nat-sim/` reproduces two peers behind separate NATs reachable only via
a public rendezvous, using rootless namespaces (`unshare -Urnm`). Run:

```bash
cd testing/nat-sim
unshare -Urnm --map-root-user env -u http_proxy -u https_proxy -u all_proxy bash punch_demo.sh
# expect: "round-trip through double-NAT confirmed ✓" and exit code 0
```

Key file: **`hyrlm.py`** is a **byte-exact** reference of the `apernet/hysteria`
`HYRLMv1` punch codec (magic `HYRLMv1\0`, 8-byte salt, payload XOR with
`SHA256(obfsKey||salt)`, Hello=0x01/Ack=0x02, 16-byte nonce) and STUN Binding
codec. **The Rust punch codec MUST produce byte-identical packets to this** —
use it as the unit-test oracle. `rendezvous.py` is a faithful-subset
`hysteria-realm-server` the Rust rendezvous client can be tested against.

See `testing/nat-sim/README.md` for full details, the topology diagram, and the
`NAT_CONE=full|restricted` knob (full-cone is the reliable green path; restricted
exposes the known simultaneous-open conntrack race that real punchers mitigate).

## Verified protocol facts (so you don't re-research)

- **Rendezvous HTTP API** (bearer token): `POST /v1/{realm}` register →
  `{session_id,ttl}`; `GET /v1/{realm}/events` SSE (`punch`/`heartbeat_ack`);
  `POST /v1/{realm}/heartbeat`; `DELETE /v1/{realm}`; `POST /v1/{realm}/connect`
  (blocks ≤10s) ; `POST /v1/{realm}/connects/{nonce}`. nonce=16B hex(32),
  obfs=32B hex(64). Full details in `DESIGN.md` §1.
- **Punch packet**: see `hyrlm.py` / `DESIGN.md` §1 (byte-exact).
- **STUN**: standard RFC 5389 Binding, parse `XOR-MAPPED-ADDRESS`.
- Sources: https://v2.hysteria.network/docs/advanced/Realms/ ,
  https://v2.hysteria.network/docs/developers/Protocol/ ,
  https://github.com/apernet/hysteria-realm-server ,
  https://github.com/apernet/hysteria/tree/master/extras/realm

## Next action on resume

Phases 0–8 **and** the binary wiring + CI are done; a single client works
end-to-end through the real binaries. Next: multi-client shared-socket demux,
ss-UDP over QUIC datagrams, PATH B (direct-TCP upgrade) end-to-end, then Phase 9
(DNS-01 ACME, resilience, ACL on the realm server path).

Use the sandbox build recipe above (PATH + CMAKE_POLICY_VERSION_MINIMUM +
CARGO_TARGET_DIR off the mount). Verify with:
`cargo test -p shadowsocks-realm`,
`cargo test -p shadowsocks --features realm --test realm_e2e`,
`cargo build --features realm --bin sslocal --bin ssserver`, then
`SS_BIN_DIR=$CARGO_TARGET_DIR/debug bash testing/realm-e2e/run_binary_e2e.sh`.

> Sandbox disk note: the debug target dir is large; the workspace volume can fill
> during the final binary link ("No space left on device"). Remove
> `$CARGO_TARGET_DIR/debug/incremental` and stale integration-test executables in
> `deps/` to reclaim space (the `lib*.rlib` files are the ones needed to link).

## Repo additions

```
DESIGN.md                      architecture + roadmap (status note at top of §7)
HANDOFF.md                     this file
configs/realm/{server,client}.json5   intended realm config schema
crates/shadowsocks-realm/      NEW transport crate (clippy clean, tests pass)
  README.md  Cargo.toml
  src/lib.rs  error.rs  url.rs  stun.rs  punch.rs  socket.rs
  src/quic.rs  tls.rs  control.rs  path_manager.rs  session.rs
  src/rendezvous/{mod,client,events,types}.rs
  src/portmap/{mod,upnp,natpmp}.rs
  tests/{rendezvous_mock,stun_mock,punch_local,quic_local,control_upgrade,portmap_graceful}.rs
crates/shadowsocks/src/realm.rs    NEW — ss-over-QUIC bridge (RealmClient/RealmServer)
crates/shadowsocks/tests/realm_e2e.rs   NEW — full-stack ss-over-realm e2e
testing/nat-sim/               double-NAT testbed (validated)
  README.md  topology.sh  hyrlm.py  stun_server.py  rendezvous.py
  peer.py  punch_demo.sh  _punchtest.py
testing/realm-e2e/run_binary_e2e.sh   NEW — real-binary e2e (curl via SOCKS→realm)
.github/workflows/realm.yml    NEW — CI: test + clippy + library e2e + binary e2e
```
Modified upstream files:
- Additive feature wiring (no default-build logic change): `Cargo.toml`,
  `crates/shadowsocks/Cargo.toml` (+`quinn`/`shadowsocks-realm` optional deps,
  `realm` feature, `pub mod realm`), `crates/shadowsocks-service/Cargo.toml`
  (`realm` feature), `crates/shadowsocks/src/lib.rs`.
- Binary wiring: `crates/shadowsocks-service/src/config.rs` (realm config types +
  field + parse/serialize + tests), `.../src/server/mod.rs` (`run_realm_server`),
  `.../src/local/loadbalancing/server_data.rs` (RealmClient cache on ServerIdent),
  `.../src/local/net/tcp/auto_proxy_stream.rs` (`Realm` stream variant + dial),
  `.../src/manager/server.rs` (struct-literal field).
