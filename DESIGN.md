# shadowsocks-rust-realms — Design & Roadmap

Adapt **Hysteria Realms** (P2P UDP hole-punching) onto shadowsocks so an
`ssserver` behind NAT/CGNAT can be reached by `sslocal` **without a public IP
or port forwarding**, while keeping the shadowsocks proxy protocol unchanged.

**Transport strategy (per your decision):** a **dual-path** design — establish
**QUIC over the punched UDP path immediately** so traffic flows from the first
moment, while in the background trying **UPnP / NAT-PMP** to map a direct **TCP**
port. When the TCP path becomes available, **seamlessly upgrade** to native
shadowsocks TCP (faster, no QUIC overhead). The upgrade is negotiated **in-band
over the existing QUIC connection**, so the unmodified Go rendezvous server
never needs to know about TCP.

Status: design proposal (v2, dual-path), awaiting approval before Phase 0.

---

## 1. What "Realms" actually is

Realms is *not* a proxy protocol. It is a generic UDP NAT-traversal framework
made of three reusable pieces:

1. **Rendezvous client** — a tiny HTTP/SSE client that talks to a rendezvous
   server (`realm://token@host/realm-name`). It only introduces peers; it never
   relays traffic.
2. **STUN discovery** — each side queries STUN servers over its own UDP socket
   to learn its public `ip:port`. Standard RFC 5389 Binding, `XOR-MAPPED-ADDRESS`.
3. **UDP hole punching** — both sides simultaneously fire obfuscated UDP
   Hello/Ack packets at each other's candidate addresses until a hole opens.

Output: a **single connected UDP socket whose remote peer is the other side**,
reachable directly P2P. What runs on top is the integrator's choice. Hysteria
runs QUIC; **we run shadowsocks**, and additionally try to graduate to direct TCP.

### Wire details we must match (verified against `apernet/hysteria`)

**Rendezvous HTTP API** (`hysteria-realm-server`), all `Authorization: Bearer <token>`:

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /v1/{realm}` | token | Server registers realm, body `{"addresses":[...]}` → `{session_id, ttl}` |
| `GET  /v1/{realm}/events` | session_id | Server's SSE stream: `punch` + `heartbeat_ack` events |
| `POST /v1/{realm}/heartbeat` | session_id | Refresh TTL, optionally replace addresses |
| `DELETE /v1/{realm}` | session_id | Deregister |
| `POST /v1/{realm}/connect` | token | Client asks to connect; body `{addresses,nonce,obfs}`; **blocks ≤10 s** for the server to post fresh addrs, then returns peer `{addresses,nonce,obfs}` |
| `POST /v1/{realm}/connects/{nonce}` | session_id | Server posts fresh STUN addrs in reply to a `punch` SSE event |

`nonce` = 16 random bytes as 32 hex chars. `obfs` = 32 random bytes as 64 hex chars.

**Punch packet wire format** (`extras/realm/punch.go`, exact):

```
[8 bytes]  salt (random per packet)
[payload]  XOR-obfuscated with mask = SHA256(obfsKey || salt), repeating mask
plain payload (25-byte header + 0..1024 random padding):
  [8]  magic = "HYRLMv1\0"  (48 59 52 4C 4D 76 31 00)
  [1]  type: 0x01 Hello, 0x02 Ack
  [16] nonce (must equal the connect nonce)
  [N]  random padding, 0..1024 bytes
```

XOR: `mask = SHA256(obfsKey || salt)` (32 bytes); `payload[i] ^= mask[i % 32]`.
Min wire len 33, max 1057. Bad magic / nonce mismatch / wrong length → discard.

**STUN**: standard Binding request; parse `XOR-MAPPED-ADDRESS` (fallback
`MAPPED-ADDRESS`). Multiple STUN servers reveal symmetric-NAT port patterns.

**Compatibility scope:** we match the *rendezvous* and *punch* wire formats so
our nodes work with the **stock open-source `hysteria-realm-server`** (run by
you, Go). We do **not** interoperate with Hysteria *proxy* nodes — the payload
over the path is shadowsocks. Two ss-realms nodes talk to each other.

---

## 2. Dual-path transport architecture

```
                 ┌──────────────── rendezvous (Go, unmodified) ───────────────┐
                 │  register / SSE punch / connect — introductions only        │
                 └─────────────────────────────────────────────────────────────┘
                              ▲                         ▲
            STUN + register   │                         │  STUN + connect
                              │                         │
        ssserver (behind NAT) │                         │ sslocal (client)
                              ▼                         ▼
                     ── UDP hole punching (HYRLMv1 Hello/Ack) ──
                              │   punched direct UDP path   │
                              ▼                             ▼
   PATH A (always, immediate):  QUIC (quinn) over punched socket
                              │  carries ss AEAD streams + ss-UDP datagrams
                              │
   PATH B (opportunistic, background): UPnP/NAT-PMP maps a TCP port on the
   server's router ──► server announces "TCP @ ip:port" *in-band over QUIC* ──►
   client dials it, verifies ss AEAD, and routes NEW connections over native
   shadowsocks TCP. QUIC streams already open drain naturally. Seamless.
```

### Why this shape

- **QUIC first** = zero-wait usability and works on any hole-punchable NAT.
  quinn gives reliability, multiplexing (a bidi stream per proxied TCP conn),
  datagrams (ss-UDP), and congestion control for free.
- **TCP via UPnP/NAT-PMP** = when the router cooperates, we get a clean direct
  TCP port and fall back to **plain shadowsocks TCP** — best throughput, lowest
  CPU, and no QUIC framing overhead.
- **In-band upgrade over QUIC** keeps the Go rendezvous untouched: it only ever
  carries UDP punch addresses; the TCP endpoint is signaled on the working QUIC
  link, after auth.

### shadowsocks stays the proxy protocol on both paths

```
PATH A:  ss AEAD stream  ──► QUIC bidi stream ──► quinn ──► punched UDP socket
PATH B:  ss AEAD stream  ──► native TCP socket (UPnP-mapped port)   [unchanged ss]
```

The same `crypto_io` / relay code runs over either an `AsyncRead+AsyncWrite`
QUIC stream or a `TcpStream`. ss AEAD remains the real end-to-end auth on both,
independent of QUIC's TLS.

### Seamless upgrade — two granularities

- **Per-new-connection switch (default, truly seamless):** a client-side
  `PathManager` picks the best currently-available path for each *new* SOCKS/HTTP
  request. Before TCP is ready → QUIC. After → TCP. In-flight QUIC streams finish
  on QUIC. No user-visible disruption, modest implementation.
- **Mid-stream migration (optional, stretch):** moving a single live flow from
  QUIC to TCP needs a custom resumption layer (per-flow sequence numbers +
  re-sync handshake). Deferred to a later, optional phase; not required for the
  feature to be useful.

### In-band control protocol (over a dedicated QUIC bidi "control" stream)

A small length-prefixed message set, opened right after ss auth on the QUIC link:

```
ControlMsg ::= [varint type][varint len][bytes body]
  type 0x01 TcpEndpointOffer { addresses: [ip:port], token: [32B] }   server→client
  type 0x02 TcpEndpointAck   { accepted: bool }                       client→server
  type 0x03 Ping / 0x04 Pong { ts }                                   keepalive/RTT
  type 0x05 TcpPathDown      { }                                      either, demote to QUIC
```

`token` lets the server bind the incoming direct-TCP connection to this
authenticated session (the client presents it in the first TCP handshake bytes,
under ss AEAD), preventing a stranger who portscans the UPnP port from being
treated as this session.

---

## 3. Crate / module layout

```
crates/
  shadowsocks-realm/                 ← NEW, protocol-agnostic, no ss deps
    src/
      lib.rs
      rendezvous/  mod.rs client.rs events.rs types.rs   rendezvous HTTP+SSE
      stun.rs                        RFC 5389 binding discovery
      punch.rs                       HYRLMv1 codec + Hello/Ack punch loop
      socket.rs                      PunchedSocket: connected UDP, demux
      portmap/  mod.rs upnp.rs natpmp.rs                 UPnP-IGD + NAT-PMP/PCP
      url.rs                         realm:// / realm+http:// parsing
      error.rs
  shadowsocks/
    src/net/realm/                   ← carrier + path manager (feature `realm`)
      mod.rs
      quic/  client.rs server.rs stream.rs udp_adapter.rs   QUIC over PunchedSocket
      control.rs                     in-band control protocol
      path_manager.rs                per-connection QUIC↔TCP selection
      tls.rs                         self-signed+pin AND ACME/real-cert
  shadowsocks-service/
    src/local/...                    sslocal: dial via realm PathManager
    src/server/...                   ssserver: register realm, accept QUIC+TCP
```

`shadowsocks-realm` has **zero** shadowsocks deps (independently testable,
matches upstream's "generic framework" intent). The carrier/path-manager live in
`shadowsocks` because they need the AEAD stream + `ServerConfig`.

### New dependencies (all behind `realm` feature)

- `quinn`, `rustls` — QUIC carrier.
- `rcgen` — self-signed certs; `rustls-acme` (or `instant-acme` + DNS-01) — ACME.
- `reqwest` (already optional) with streaming — rendezvous HTTP + SSE.
- `igd-next` (async/tokio) — UPnP-IGD port mapping; small NAT-PMP/PCP client
  (in-house or `natpmp`-style) for routers that prefer it.
- `sha2` — punch XOR mask (SHA-256, **not** BLAKE2b).
- In-house ~150-line RFC 5389 Binding codec (avoid a heavy STUN dep; only
  Binding req/resp needed).

---

## 4. Configuration design

A server entry gains an optional `realm` object. Its presence switches that
server to realm transport; absence = ordinary shadowsocks (fully backward
compatible). New feature flag `realm` (off by default; opt-in via `--features realm`).

**Server (`ssserver`):**
```jsonc
{
  "server": "0.0.0.0", "server_port": 8388,
  "password": "…", "method": "aes-256-gcm",
  "realm": {
    "rendezvous": "realm://my-secret-token@realm.example.com/my-cabin-1f3a8c2e9b",
    "stun_servers": ["stun.l.google.com:19302"],     // optional
    "quic_tls": { "self_signed": true },             // or ACME block below
    "tcp_upgrade": {                                  // PATH B; optional, default on
      "enable": true,
      "methods": ["upnp", "natpmp"],                 // try in order
      "external_port": 0                             // 0 = ask router to choose
    }
  }
}
```

ACME variant for `quic_tls` (and reused for any TLS-fronted path):
```jsonc
"quic_tls": { "acme": { "domains": ["nat.example.com"],
                        "email": "you@example.com",
                        "dns01_provider": "…" } }   // DNS-01 (no inbound needed)
```

**Client (`sslocal`):**
```jsonc
"realm": {
  "rendezvous": "realm://my-secret-token@realm.example.com/my-cabin-1f3a8c2e9b",
  "stun_servers": ["stun.l.google.com:19302"],
  "quic_tls": { "pin_sha256": "…", "insecure": true },  // self-signed pin
  "prefer_tcp": true                                     // accept PATH B upgrades
}
```

URI query params `?stun=` and `?lport=` honored, matching Hysteria.

---

## 5. Control flow

**Server startup (realm mode):**
1. Parse `realm.rendezvous`. Bind one UDP socket (ephemeral or `lport`).
2. STUN-discover reflexive addresses; `POST /v1/{realm}` → `{session_id, ttl}`.
3. Open `GET /events` SSE; run heartbeat loop before `ttl`.
4. **Background PATH B:** attempt UPnP-IGD / NAT-PMP to map an external TCP port
   to a local ss TCP listener; remember the public `ip:port` if it succeeds.
5. On each `punch` SSE `{addresses, nonce, obfs}`:
   a. Fresh STUN → `POST /connects/{nonce}`.
   b. Run punch loop toward client `addresses` (nonce+obfs).
   c. quinn **server** handshake over the punched socket; authenticate ss AEAD.
   d. Accept QUIC bidi streams into the existing server relay; ss-UDP via datagrams.
   e. If a TCP port is mapped, send `TcpEndpointOffer` on the control stream;
      also accept native ss-TCP connections on the mapped port and bind them to
      the session via the offered `token`.

**Client startup (realm mode), on first use / per server:**
1. Parse URI; bind UDP socket; STUN-discover.
2. `POST /connect {addresses,nonce,obfs}` → peer addresses.
3. Punch loop with same nonce+obfs → `PunchedSocket`.
4. quinn **client** handshake (verify pin or ACME cert) + ss AEAD auth.
5. Register both transports with `PathManager`. On `TcpEndpointOffer`, dial the
   TCP endpoint, verify ss AEAD + token, mark TCP path UP.
6. Per new SOCKS/HTTP request: `PathManager` opens a QUIC stream (TCP not ready)
   or a native ss-TCP conn (TCP ready). ss-UDP → QUIC datagrams (UDP stays on QUIC).

**Punch loop (symmetric, both sides):**
- Send `Hello` (0x01) to every candidate peer address at a fixed interval until
  success/timeout.
- On valid `Hello` → reply `Ack` (0x02) to its source.
- On valid `Ack` (or first valid Hello from the chosen addr) → confirm that
  source as peer, "connect" the UDP socket to it, stop punching, hand to QUIC.
- Demux on the shared port: STUN responses, punch packets, then QUIC packets —
  route by inspection (magic / transaction-id / fallthrough to QUIC).

---

## 6. Risks & decisions

- **Symmetric NAT both sides** → unsolvable for punching (documented). PATH B
  (UPnP) may still save it; otherwise surface a clear error + recommend a
  public-IP server. Predictable-symmetric multi-STUN heuristic = later.
- **UPnP availability varies** wildly by router; NAT-PMP/PCP covers some Apple/
  others. PATH B is strictly best-effort — QUIC always backstops it, so a failed
  mapping never breaks connectivity, only forgoes the TCP speedup.
- **Seamless upgrade granularity**: per-new-connection by default; true mid-flow
  migration is an optional later phase (custom resumption layer).
- **QUIC dep**: adds quinn/rustls + handshake latency, removes a large class of
  reliability bugs we'd otherwise own. Accepted.
- **Edition/MSRV**: repo is edition 2024, rust 1.91, `panic = "abort"`. Confirm
  quinn/rustls/igd-next build under these in Phase 0.
- **ACME without inbound**: only **DNS-01** works in NAT mode (HTTP-01/TLS-ALPN
  need an inbound port). Self-signed+pin remains the zero-config default.

---

## 7. Phased roadmap (each phase ends compiling + tested)

> **Implementation status (current):** Phases 0–6 ✅ complete & tested.
> Phases 7–8 ✅ delivered and tested **at the library/bridge level**: a real
> shadowsocks AEAD session runs over the full realm stack (rendezvous + STUN +
> HYRLMv1 punch + QUIC carrier) in an automated end-to-end test
> (`crates/shadowsocks/tests/realm_e2e.rs`). The remaining **binary-level**
> wiring — reading the `realm` config block in `sslocal`/`ssserver` and routing
> their run-loops through `shadowsocks::realm::{RealmClient, RealmServer}` — plus
> multi-client shared-socket punch/QUIC demultiplexing, are the documented final
> productization steps. Phase 9 (ACME/hardening) and Phase 10 (mid-stream
> migration) are not started.
>
> **Note:** the QUIC carrier + control + path-manager live in the
> `shadowsocks-realm` crate (`quic`, `control`, `path_manager`, `tls`,
> `session`) rather than under `shadowsocks/src/net/realm/` as originally
> sketched in §3 — they are protocol-agnostic, so keeping them in the
> dependency-free crate makes them independently testable. The thin ss-specific
> bridge (`ProxyClientStream`/`ProxyServerStream` over a QUIC stream) is
> `shadowsocks/src/realm.rs`.


**Phase 0 — Scaffolding & deps.** Create `shadowsocks-realm` crate; wire the
`realm` feature across the workspace; add deps; confirm quinn/rustls/igd-next
build under edition 2024 / MSRV. ✅ `cargo build` clean, empty crate.

**Phase 1 — Rendezvous client.** HTTP API (register, events/SSE, heartbeat,
connect, connects, delete) + `realm://` parsing. ✅ tests vs mock HTTP; optional
live smoke vs local `hysteria-realm-server`.

**Phase 2 — STUN discovery.** RFC 5389 Binding codec, `XOR-MAPPED-ADDRESS`,
multi-server discovery. ✅ canned-response tests + live public STUN.

**Phase 3 — Punch codec + loop.** Byte-exact `HYRLMv1` codec (tests vs Go
layout), Hello/Ack loop, `PunchedSocket` with STUN/punch demux. ✅ two local
sockets punch in an integration test.

**Phase 4 — QUIC carrier.** quinn client/server over the punched socket via a
custom `AsyncUdpSocket`; self-signed+pin TLS; map bidi streams + datagrams.
✅ echo a stream + a datagram P2P over a locally punched path.

**Phase 5 — UPnP/NAT-PMP port mapping.** `portmap` module; map/refresh/release
an external TCP port; detect external IP. ✅ unit tests + live test on a UPnP
router (and graceful no-op when unavailable).

**Phase 6 — In-band control + PathManager.** Control protocol over QUIC; client
`PathManager` with per-new-connection QUIC↔TCP selection + token-bound TCP
handshake. ✅ simulated upgrade test: connections start on QUIC, move to TCP
after an offer, fall back on TCP failure.

**Phase 7 — shadowsocks wiring (client).** sslocal dials a realm server through
`PathManager`; ss AEAD over QUIC stream or native TCP. ✅ sslocal proxies TCP to
a stub over a realm path.

**Phase 8 — shadowsocks wiring (server).** ssserver registers a realm, accepts
QUIC streams + native ss-TCP into the existing relay; ss-UDP over datagrams;
emits TCP offers. ✅ **full end-to-end**: real sslocal ⇄ realm ⇄ real ssserver
behind NAT, TCP+UDP, with a verified QUIC→TCP upgrade; curl through it.

**Phase 9 — TLS/ACME + hardening + docs.** DNS-01 ACME for the QUIC carrier;
reconnect/heartbeat resilience, timeouts, metrics/logging, config validation,
README + example configs, NAT-type diagnostics. ✅ clippy clean, docs landed.

**Phase 10 (optional) — true mid-stream migration.** Custom resumption layer to
move a single live flow QUIC→TCP. Only if you want it after Phase 8.

---

## 8. Resolved decisions

- **Carrier:** QUIC (quinn) immediately, + UPnP/NAT-PMP→native-TCP upgrade,
  seamless per-new-connection switch (mid-flow migration optional, Phase 10).
- **TLS:** self-signed + SHA-256 pin by default **and** ACME/real-cert
  (DNS-01) support.
- **Rendezvous:** compatibility only — you self-host the stock Go
  `hysteria-realm-server`; no rendezvous code in this repo.
- **Feature flag:** `realm` off by default, **opt-in only** (`--features realm`).
  Deliberately not in `full`/`full-extra`: it pulls a heavy dep tree (quinn,
  rustls, aws-lc, reqwest, igd-next) the project's default MSRV/clippy/release CI
  isn't set up for. It has its own CI (`.github/workflows/realm.yml`).
