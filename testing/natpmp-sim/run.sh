#!/usr/bin/env bash
# Real NAT-PMP gateway testbed (PATH B port mapping).
#
# Topology (rootless user+net+mount namespace, no real root):
#
#     [wan] 203.0.113.2 ──veth── 203.0.113.1 [gw] 10.0.0.1 ──veth── 10.0.0.2 [srv]
#                                  (MASQUERADE + NAT-PMP daemon + DNAT)
#
# `srv` sits behind the NAT gateway with NO inbound port. It asks the gateway for
# an inbound TCP port using THIS repo's NAT-PMP client (portmap::natpmp via the
# `natpmp_map` example). The gateway daemon answers the NAT-PMP protocol AND
# installs a real iptables DNAT. Then the external `wan` client connects to the
# mapped public port and reaches `srv` — proving real port mapping + real NAT
# forwarding, equivalent to OpenWrt's miniupnpd.
#
# Run:
#   cargo build -p shadowsocks-realm --example natpmp_map
#   unshare -Urnm --map-root-user env -u http_proxy -u https_proxy -u all_proxy \
#       bash testing/natpmp-sim/run.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
HELPER="${NATPMP_MAP_BIN:-$REPO/target/debug/examples/natpmp_map}"
PY="${PYTHON:-python3}"

INT_PORT=18080
EXT_PORT=29090
WAN_IP=203.0.113.1

[ -x "$HELPER" ] || { echo "helper not found: $HELPER
  build it: cargo build -p shadowsocks-realm --example natpmp_map
  or set NATPMP_MAP_BIN to its path"; exit 1; }

mount -t tmpfs none /run 2>/dev/null || true
mkdir -p /run/netns

ip netns add gw; ip netns add srv; ip netns add wan
for n in gw srv wan; do ip -n "$n" link set lo up; done

# gw <-> srv (LAN) and gw <-> wan (WAN)
ip link add lan-gw netns gw type veth peer name lan-srv netns srv
ip -n gw addr add 10.0.0.1/24 dev lan-gw;  ip -n gw link set lan-gw up
ip -n srv addr add 10.0.0.2/24 dev lan-srv; ip -n srv link set lan-srv up
ip link add wan-gw netns gw type veth peer name wan-cli netns wan
ip -n gw addr add 203.0.113.1/24 dev wan-gw;  ip -n gw link set wan-gw up
ip -n wan addr add 203.0.113.2/24 dev wan-cli; ip -n wan link set wan-cli up

ip -n srv route add default via 10.0.0.1
ip -n wan route add default via 203.0.113.1

ip netns exec gw sysctl -q -w net.ipv4.ip_forward=1
ip netns exec gw sysctl -q -w net.ipv4.conf.all.rp_filter=0
ip netns exec gw iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o wan-gw -j MASQUERADE

cleanup() {
  kill $(jobs -p) 2>/dev/null || true
  ip netns del gw 2>/dev/null || true
  ip netns del srv 2>/dev/null || true
  ip netns del wan 2>/dev/null || true
}
trap cleanup EXIT

# --- echo server behind the NAT (srv) ---
ip netns exec srv "$PY" - "$INT_PORT" <<'PYEOF' &
import socket, sys, threading
port = int(sys.argv[1])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.listen(8)
print(f"[echo] srv listening :{port}", flush=True)
def handle(c):
    while True:
        d = c.recv(4096)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF
sleep 0.5

# --- NAT-PMP gateway daemon (gw) ---
ip netns exec gw "$PY" "$HERE/natpmp_gateway.py" 10.0.0.1 "$WAN_IP" &
sleep 0.5

echo "### srv requests a NAT-PMP mapping using our portmap::natpmp client ###"
MAP_OUT="$(ip netns exec srv "$HELPER" 10.0.0.1 "$INT_PORT" "$EXT_PORT")"
echo "$MAP_OUT"
echo "$MAP_OUT" | grep -q "MAPPED external=${WAN_IP}:${EXT_PORT}" \
  || { echo "FAIL: unexpected mapping response"; exit 1; }

echo "### real iptables DNAT installed in the gateway namespace ###"
ip netns exec gw iptables -t nat -S PREROUTING | grep "dport ${EXT_PORT}" \
  || { echo "FAIL: no DNAT rule installed"; exit 1; }

echo "### external wan client connects to ${WAN_IP}:${EXT_PORT} (through real NAT) ###"
RESULT="$(ip netns exec wan "$PY" - "$WAN_IP" "$EXT_PORT" <<'PYEOF'
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.settimeout(5); s.connect((ip, port))
s.sendall(b"natpmp-real-ok")
sys.stdout.write(s.recv(64).decode()); s.close()
PYEOF
)"
echo "echo returned: '${RESULT}'"
if [ "$RESULT" = "natpmp-real-ok" ]; then
  echo "### RESULT: real NAT-PMP mapping + NAT forwarding confirmed ✓ ###"
  exit 0
fi
echo "FAIL: traffic did not traverse the mapped port"
exit 1
