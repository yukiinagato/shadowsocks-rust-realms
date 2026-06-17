# Double-NAT testbed for shadowsocks-rust-realms

A rootless (no real root needed) network-namespace harness that reproduces two
peers behind **separate NATs**, reachable only through a public rendezvous —
the exact scenario Hysteria Realms / this project solves. It is used to validate
NAT traversal end-to-end, and will host the real `sslocal`/`ssserver` binaries
once they are built.

## Topology

```
        inet ns  (public segment 198.51.100.0/24, bridge br0 = 198.51.100.1)
        ├─ rendezvous.py   :8080   (faithful subset of hysteria-realm-server API)
        └─ stun_server.py  :3478   (RFC 5389 Binding responder)
              │ bridge                              │ bridge
        natC (198.51.100.10, NAT)             natS (198.51.100.20, NAT)
              │ 192.168.10.1                        │ 192.168.20.1
            cli 192.168.10.2                      srv 192.168.20.2
```

`srv` has **no inbound path** from `inet`/`cli` except a hole opened through
`natS`. No port forwarding, no public IP on the host.

## Requirements

A Linux kernel that allows unprivileged user namespaces (`unshare -Urnm`).
Pure-stdlib Python 3; no external packages. Everything is torn down when the
process exits.

## Run

```bash
cd testing/nat-sim

# Build the topology and run a basic reachability smoke test:
unshare -Urnm --map-root-user bash topology.sh up

# Full end-to-end: STUN -> rendezvous -> hole punch -> data round-trip:
unshare -Urnm --map-root-user env -u http_proxy -u https_proxy -u all_proxy \
  bash punch_demo.sh
```

Expected tail:

```
[server] got Ack from 198.51.100.10:52000 -> hole OPEN
[client] got Ack from 198.51.100.20:51000 -> hole OPEN
[server] RESULT: data path confirmed ✓
[client] RESULT: round-trip through double-NAT confirmed ✓
### demo exit code: 0 ###
```

(The `env -u …_proxy` strips the sandbox's HTTP proxy, which is unreachable
inside the namespace.)

## NAT model

`topology.sh` honours `NAT_CONE`:

- `full` (default) — endpoint-independent mapping **and** filtering. Peers bind
  fixed source ports (the Realms `lport` feature, `CLI_LPORT`/`SRV_LPORT`), so
  the public mapping is deterministic `public:LPORT <-> host:LPORT`. This is the
  textbook full-cone router, listed as always-punchable in the
  [Realms NAT matrix](https://v2.hysteria.network/docs/advanced/Realms/#nat-compatibility).
  Reliable and reproducible.
- `restricted` — `MASQUERADE` with conntrack filtering. Closer to a stricter
  home router and subject to the well-known **simultaneous-open conntrack race**
  (an inbound punch packet arriving before the local outbound mapping exists
  creates a phantom conntrack entry that forces nf_nat to remap the legit flow).
  Real punchers mitigate this with the TTL trick and retries; provided here for
  experimentation, not as the default green-path test.

## What this validates (Python reference, runs today)

| Component | Status | Notes |
|---|---|---|
| `HYRLMv1` punch packet codec | ✅ byte-exact | `hyrlm.py` self-test asserts the exact `apernet/hysteria` layout (magic, SHA-256 salt-XOR, Hello/Ack, nonce) |
| STUN discovery through NAT | ✅ | both peers learn their public `ip:port`; mapping confirmed endpoint-independent |
| Rendezvous register/connect/connects | ✅ | full nonce handshake across both NATs |
| UDP hole punch (full-cone) | ✅ 3/3 | Hello/Ack opens the hole |
| Application data over the hole | ✅ | PING/PONG round-trip client⇄server |

These reference scripts also serve as an **oracle** for the Rust implementation:
the Rust punch codec is expected to produce byte-identical packets to `hyrlm.py`,
and the Rust rendezvous client can be tested against `rendezvous.py`.

## Files

| File | Role |
|---|---|
| `topology.sh` | builds/tears down the namespaces; sourceable (`build`/`smoke`) |
| `hyrlm.py` | wire-faithful HYRLMv1 punch codec + STUN codec (+ self-test) |
| `stun_server.py` | minimal STUN Binding responder |
| `rendezvous.py` | faithful-subset rendezvous server (HTTP + long-poll events) |
| `peer.py` | a Realms peer: STUN → rendezvous → punch → data exchange |
| `punch_demo.sh` | orchestrates the full end-to-end demo |
| `_punchtest.py` | minimal two-socket punch diagnostic (fixed nonce/obfs) |

## Next: testing the real binaries

Once `sslocal`/`ssserver` with `--features realm` are built, the same topology
hosts them directly:

```bash
# (sketch) inside the unshared namespace:
ip netns exec srv ssserver -c server-realm.json   # registers realm via rendezvous
ip netns exec cli sslocal  -c client-realm.json   # SOCKS5 on 127.0.0.1:1080
ip netns exec cli curl -x socks5h://127.0.0.1:1080 http://<target-in-inet>/
```

with `rendezvous.py`/`stun_server.py` (or the real Go `hysteria-realm-server`)
running in `inet`.
