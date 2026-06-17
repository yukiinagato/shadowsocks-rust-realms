#!/usr/bin/env bash
#
# Binary end-to-end test for the realm transport.
#
# Brings up, all on loopback:
#   - the rendezvous mock  (testing/nat-sim/rendezvous.py)
#   - the STUN mock        (testing/nat-sim/stun_server.py)
#   - a target HTTP server (python http.server)
#   - a real `ssserver` in realm mode (prints its self-signed cert pin)
#   - a real `sslocal`  in realm mode (SOCKS5), pinned to that cert
# then curls a URL through sslocal's SOCKS5 proxy and checks the body came back
# through the full realm path:  curl → sslocal → QUIC(punched) → ssserver → target.
#
# Usage:  testing/realm-e2e/run_binary_e2e.sh [path-to-bin-dir]
#   bin dir defaults to $SS_BIN_DIR, else target/debug.
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAT_SIM="$REPO_ROOT/testing/nat-sim"
BIN_DIR="${1:-${SS_BIN_DIR:-$REPO_ROOT/target/debug}}"
SSSERVER="$BIN_DIR/ssserver"
SSLOCAL="$BIN_DIR/sslocal"

PY="${PYTHON:-python3}"
WORK="$(mktemp -d)"
PIDS=()

log()  { echo "[e2e] $*"; }
die()  { echo "[e2e] FAIL: $*" >&2; exit 1; }

cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

command -v "$PY"   >/dev/null || die "python3 not found"
command -v curl    >/dev/null || die "curl not found"
[ -x "$SSSERVER" ] || die "ssserver not found at $SSSERVER (build with --features realm)"
[ -x "$SSLOCAL"  ] || die "sslocal not found at $SSLOCAL (build with --features realm)"

# --- pick free TCP ports (rendezvous, stun-bind, target, socks) ---
free_port() { "$PY" -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
RZV_PORT=$(free_port); STUN_PORT=$(free_port); TARGET_PORT=$(free_port); SOCKS_PORT=$(free_port)
log "ports: rendezvous=$RZV_PORT stun=$STUN_PORT target=$TARGET_PORT socks=$SOCKS_PORT"

# --- target HTTP server with a known body ---
MARKER="realm-binary-e2e-ok-$$"
mkdir -p "$WORK/www"
echo "$MARKER" > "$WORK/www/marker.txt"
( cd "$WORK/www" && exec "$PY" -m http.server "$TARGET_PORT" --bind 127.0.0.1 ) >/dev/null 2>&1 &
PIDS+=($!)

# --- rendezvous + STUN mocks ---
( cd "$NAT_SIM" && exec "$PY" rendezvous.py 127.0.0.1 "$RZV_PORT" ) >"$WORK/rzv.log" 2>&1 &
PIDS+=($!)
( cd "$NAT_SIM" && exec "$PY" stun_server.py 127.0.0.1 "$STUN_PORT" ) >"$WORK/stun.log" 2>&1 &
PIDS+=($!)

# wait for rendezvous to listen
for _ in $(seq 1 50); do
    "$PY" -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$RZV_PORT))==0 else 1)" && break
    sleep 0.1
done

RENDEZVOUS="realm+http://test-token@127.0.0.1:$RZV_PORT/room-bin"
STUN="127.0.0.1:$STUN_PORT"

# --- ssserver realm config ---
cat > "$WORK/server.json5" <<EOF
{
  "server": "0.0.0.0", "server_port": 8388,
  "password": "realm-e2e-pass", "method": "aes-256-gcm",
  "realm": {
    "rendezvous": "$RENDEZVOUS",
    "stun_servers": ["$STUN"],
    "quic_tls": { "self_signed": true }
  }
}
EOF

log "starting ssserver..."
"$SSSERVER" -c "$WORK/server.json5" -v >"$WORK/server.log" 2>&1 &
PIDS+=($!)

# --- parse the self-signed cert pin printed by ssserver ---
PIN=""
for _ in $(seq 1 100); do
    PIN=$(grep -oE 'pin \(sha256\) = [0-9a-f]{64}' "$WORK/server.log" | head -1 | grep -oE '[0-9a-f]{64}')
    [ -n "$PIN" ] && break
    sleep 0.1
done
[ -n "$PIN" ] || { echo "--- server.log ---"; cat "$WORK/server.log"; die "could not read cert pin from ssserver"; }
log "server cert pin = $PIN"

# --- sslocal realm config (pinned) ---
cat > "$WORK/client.json5" <<EOF
{
  "locals": [
    { "local_address": "127.0.0.1", "local_port": $SOCKS_PORT, "protocol": "socks" }
  ],
  // Realm mode reaches the server via rendezvous, not this address; a valid
  // (non-unspecified) placeholder is required to pass config validation.
  "server": "192.0.2.1", "server_port": 8388,
  "password": "realm-e2e-pass", "method": "aes-256-gcm",
  "realm": {
    "rendezvous": "$RENDEZVOUS",
    "stun_servers": ["$STUN"],
    "quic_tls": { "pin_sha256": "$PIN" },
    "prefer_tcp": false
  }
}
EOF

log "starting sslocal..."
"$SSLOCAL" -c "$WORK/client.json5" -v >"$WORK/client.log" 2>&1 &
PIDS+=($!)

# wait for the SOCKS port
for _ in $(seq 1 50); do
    "$PY" -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$SOCKS_PORT))==0 else 1)" && break
    sleep 0.1
done

# --- curl through the SOCKS proxy (first request establishes the carrier) ---
TARGET_URL="http://127.0.0.1:$TARGET_PORT/marker.txt"
BODY=""
for attempt in $(seq 1 15); do
    BODY=$(curl -s --max-time 8 --socks5-hostname "127.0.0.1:$SOCKS_PORT" "$TARGET_URL" 2>/dev/null)
    [ "$BODY" = "$MARKER" ] && break
    sleep 1
done

if [ "$BODY" = "$MARKER" ]; then
    log "RESULT: curl through realm transport returned the expected body ✓"
    exit 0
else
    echo "--- server.log ---"; tail -30 "$WORK/server.log"
    echo "--- client.log ---"; tail -30 "$WORK/client.log"
    die "did not receive expected body (got: '${BODY:0:80}')"
fi
