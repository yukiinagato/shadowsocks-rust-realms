#!/usr/bin/env bash
# End-to-end hole-punch demo through the double-NAT testbed.
# Run with:  unshare -Urnm --map-root-user bash punch_demo.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/topology.sh"   # sourceable: exposes build()/smoke()
build

REND=198.51.100.1
STUN=198.51.100.1:3478
BASE="http://$REND:8080"
REALM="testrealm-$(head -c4 /dev/urandom | xxd -p)"

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

echo "### starting STUN + rendezvous in 'inet' ###"
ip netns exec inet python3 "$HERE/stun_server.py" $REND 3478 &
ip netns exec inet python3 "$HERE/rendezvous.py" $REND 8080 &
sleep 1

echo "### starting SERVER peer in 'srv' (behind natS, lport ${SRV_LPORT:-51000}) ###"
ip netns exec srv env REALM_LPORT="${SRV_LPORT:-51000}" \
  python3 "$HERE/peer.py" server "$BASE" "$REALM" "$STUN" &
SRV=$!
sleep 1.5

echo "### starting CLIENT peer in 'cli' (behind natC, lport ${CLI_LPORT:-52000}) ###"
ip netns exec cli env REALM_LPORT="${CLI_LPORT:-52000}" \
  python3 "$HERE/peer.py" client "$BASE" "$REALM" "$STUN" &
CLI=$!

rc=0
wait $CLI || rc=$?
wait $SRV || rc=$?
echo "### demo exit code: $rc ###"
exit $rc
