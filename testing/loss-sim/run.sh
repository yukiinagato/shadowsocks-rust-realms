#!/usr/bin/env bash
# Availability under packet loss + concurrency.
#
# Two netns connected by a veth with tc netem loss on both sides. The rendezvous,
# STUN and a realm carrier server live on one side; a realm client on the other
# punches a hole and runs many concurrent bidi streams through the QUIC carrier
# across the lossy link. QUIC retransmission must keep every stream reliable.
#
# Run:
#   cargo build -p shadowsocks-realm --example realm_probe
#   unshare -Urnm --map-root-user env -u http_proxy -u https_proxy -u all_proxy \
#       bash testing/loss-sim/run.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
NAT_SIM="$REPO/testing/nat-sim"
PROBE="${REALM_PROBE_BIN:-$REPO/target/debug/examples/realm_probe}"
PY="${PYTHON:-python3}"
LOSS="${LOSS:-3%}"
COUNT="${COUNT:-30}"
CONCURRENCY="${CONCURRENCY:-8}"

[ -x "$PROBE" ] || { echo "probe not found: $PROBE
  build it: cargo build -p shadowsocks-realm --example realm_probe"; exit 1; }

mount -t tmpfs none /run 2>/dev/null || true
mkdir -p /run/netns
ip netns add srv; ip netns add cli
ip -n srv link set lo up; ip -n cli link set lo up

ip link add s0 netns srv type veth peer name c0 netns cli
ip -n srv addr add 203.0.113.1/24 dev s0; ip -n srv link set s0 up
ip -n cli addr add 203.0.113.2/24 dev c0; ip -n cli link set c0 up

# Inject packet loss on both directions of the link.
ip netns exec srv tc qdisc add dev s0 root netem loss "$LOSS"
ip netns exec cli tc qdisc add dev c0 root netem loss "$LOSS"
echo "### link loss set to $LOSS on both sides ###"

cleanup() {
  kill $(jobs -p) 2>/dev/null || true
  ip netns del srv 2>/dev/null || true
  ip netns del cli 2>/dev/null || true
}
trap cleanup EXIT

RZV_PORT=8080
STUN_PORT=3478
RENDEZVOUS="realm+http://test-token@203.0.113.1:${RZV_PORT}/loss-room"
STUN="203.0.113.1:${STUN_PORT}"

# rendezvous + STUN + carrier server on the srv side
ip netns exec srv "$PY" "$NAT_SIM/rendezvous.py" 203.0.113.1 "$RZV_PORT" &
ip netns exec srv "$PY" "$NAT_SIM/stun_server.py" 203.0.113.1 "$STUN_PORT" &
sleep 0.6
ip netns exec srv "$PROBE" server "$RENDEZVOUS" "$STUN" &
sleep 0.8

echo "### client runs $COUNT streams (concurrency $CONCURRENCY) across the lossy link ###"
OUT="$(ip netns exec cli "$PROBE" client "$RENDEZVOUS" "$STUN" "$COUNT" "$CONCURRENCY")"
echo "$OUT"
if echo "$OUT" | grep -q "PROBE_OK ${COUNT}/${COUNT}"; then
  echo "### RESULT: all $COUNT streams succeeded under ${LOSS} loss ✓ ###"
  exit 0
fi
echo "FAIL: some streams did not complete under loss"
exit 1
