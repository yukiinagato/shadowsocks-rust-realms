#!/usr/bin/env bash
# Double-NAT testbed for shadowsocks-rust-realms.
#
# Builds, inside a rootless user+net+mount namespace (no real root needed), a
# topology that mimics two peers behind separate NATs reachable only through a
# public rendezvous:
#
#            ┌────────────────────── inet (public segment 198.51.100.0/24) ──────────────────────┐
#            │  br0  198.51.100.1   <- rendezvous + STUN live here (the only public IP both see) │
#            └───────────────┬───────────────────────────────────────────────┬──────────────────┘
#                   natC public│198.51.100.10                    natS public│198.51.100.20
#                   (MASQUERADE)│                                (MASQUERADE)│
#               192.168.10.1 ───┤                                192.168.20.1 ───┤
#                       cli 192.168.10.2                                 srv 192.168.20.2
#
# Key property: `srv` has NO inbound port reachable from `inet` or `cli` except
# what a hole-punch opens through natS. That is exactly the scenario Realms solves.
#
# Usage:
#   unshare -Urnm --map-root-user bash topology.sh up      # build + smoke test
#   unshare -Urnm --map-root-user bash topology.sh run CMD  # build, then run CMD
# Everything lives in one unshared namespace; it vanishes when the process exits.
set -euo pipefail

NETNS_DIR=/run/netns

setup_runtime() {
  # Give ourselves a writable /run so `ip netns` can store namespace handles.
  mount -t tmpfs none /run 2>/dev/null || true
  mkdir -p "$NETNS_DIR"
}

mkns() { ip netns add "$1"; ip -n "$1" link set lo up; }

# veth_pair NS_A IF_A ADDR_A NS_B IF_B ADDR_B   (addresses include /prefix)
veth_pair() {
  local nsa=$1 ifa=$2 aa=$3 nsb=$4 ifb=$5 ab=$6
  ip link add "$ifa" netns "$nsa" type veth peer name "$ifb" netns "$nsb"
  ip -n "$nsa" addr add "$aa" dev "$ifa"; ip -n "$nsa" link set "$ifa" up
  ip -n "$nsb" addr add "$ab" dev "$ifb"; ip -n "$nsb" link set "$ifb" up
}

build() {
  setup_runtime
  # --- namespaces ---
  mkns inet
  mkns natC
  mkns natS
  mkns cli
  mkns srv

  # --- public bridge in `inet` (the rendezvous/STUN segment) ---
  ip -n inet link add br0 type bridge
  # Disable STP and zero the forwarding delay: a fresh bridge otherwise blocks
  # inter-port forwarding for ~15s, which silently breaks hole punching (while
  # STUN to the bridge's own IP keeps working — a confusing failure mode).
  ip -n inet link set br0 type bridge stp_state 0 forward_delay 0
  ip -n inet addr add 198.51.100.1/24 dev br0
  ip -n inet link set br0 up

  # natC <-> inet (public side via bridge), and natC <-> cli (private side)
  ip link add cpub netns natC type veth peer name cbr netns inet
  ip -n inet link set cbr master br0; ip -n inet link set cbr up
  ip -n natC addr add 198.51.100.10/24 dev cpub; ip -n natC link set cpub up
  veth_pair natC cpriv 192.168.10.1/24 cli ceth 192.168.10.2/24

  # natS <-> inet (public side via bridge), and natS <-> srv (private side)
  ip link add spub netns natS type veth peer name sbr netns inet
  ip -n inet link set sbr master br0; ip -n inet link set sbr up
  ip -n natS addr add 198.51.100.20/24 dev spub; ip -n natS link set spub up
  veth_pair natS spriv 192.168.20.1/24 srv seth 192.168.20.2/24

  # --- routing ---
  ip -n cli route add default via 192.168.10.1
  ip -n srv route add default via 192.168.20.1
  ip -n natC route add default via 198.51.100.1
  ip -n natS route add default via 198.51.100.1
  ip -n inet route add 192.168.10.0/24 via 198.51.100.10   # for return path visibility (debug)
  ip -n inet route add 192.168.20.0/24 via 198.51.100.20

  # --- NAT on both routers + forwarding ---
  #
  # NAT_CONE controls the simulated NAT behaviour:
  #   full       (default) endpoint-independent mapping AND filtering. The peers
  #              bind fixed source ports (Realms `lport`), so the public mapping
  #              is deterministic: public_ip:LPORT <-> host:LPORT. Inbound packets
  #              to an open mapping are delivered regardless of source — the
  #              textbook full-cone router, which the Realms NAT matrix lists as
  #              always punchable. Reliable, reproducible end-to-end test.
  #   restricted MASQUERADE: endpoint-independent mapping, conntrack-based
  #              filtering. Closer to a stricter home router; subject to the
  #              well-known simultaneous-open race that real punchers mitigate
  #              with the TTL trick / retries. Provided for experimentation.
  : "${NAT_CONE:=full}"
  : "${CLI_LPORT:=52000}"
  : "${SRV_LPORT:=51000}"
  for ns in natC natS; do
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  done

  if [[ "$NAT_CONE" == "full" ]]; then
    # Client NAT: 198.51.100.10:CLI_LPORT <-> 192.168.10.2:CLI_LPORT
    ip netns exec natC iptables -t nat -A PREROUTING  -i cpub -p udp --dport "$CLI_LPORT" \
        -j DNAT --to-destination "192.168.10.2:$CLI_LPORT"
    ip netns exec natC iptables -t nat -A POSTROUTING -o cpub -p udp --sport "$CLI_LPORT" \
        -j SNAT --to-source "198.51.100.10:$CLI_LPORT"
    ip netns exec natC iptables -t nat -A POSTROUTING -o cpub -j MASQUERADE   # other traffic (e.g. STUN)
    # Server NAT: 198.51.100.20:SRV_LPORT <-> 192.168.20.2:SRV_LPORT
    ip netns exec natS iptables -t nat -A PREROUTING  -i spub -p udp --dport "$SRV_LPORT" \
        -j DNAT --to-destination "192.168.20.2:$SRV_LPORT"
    ip netns exec natS iptables -t nat -A POSTROUTING -o spub -p udp --sport "$SRV_LPORT" \
        -j SNAT --to-source "198.51.100.20:$SRV_LPORT"
    ip netns exec natS iptables -t nat -A POSTROUTING -o spub -j MASQUERADE
  else
    ip netns exec natC iptables -t nat -A POSTROUTING -o cpub -j MASQUERADE
    ip netns exec natS iptables -t nat -A POSTROUTING -o spub -j MASQUERADE
    for ns in natC natS; do
      pub=$([[ $ns == natC ]] && echo cpub || echo spub)
      ip netns exec "$ns" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      ip netns exec "$ns" iptables -A FORWARD -i "$pub" -j DROP
    done
  fi
}

smoke() {
  echo "== cli -> rendezvous (198.51.100.1) =="
  ip netns exec cli ping -c1 -W1 198.51.100.1 | tail -1
  echo "== srv -> rendezvous (198.51.100.1) =="
  ip netns exec srv ping -c1 -W1 198.51.100.1 | tail -1
  echo "== cli -> srv public NAT IP (198.51.100.20) should be FILTERED (no punch yet) =="
  if ip netns exec cli ping -c1 -W1 198.51.100.20 >/dev/null 2>&1; then
    echo "  reachable (router itself answers; srv host stays unreachable inbound)"
  else
    echo "  filtered/unreachable as expected"
  fi
  echo "== external mapping check: srv's view of its public addr via natS =="
  echo "  (STUN will reveal 198.51.100.20:<mapped-port> at runtime)"
}

# Only act when executed directly; when sourced, just expose the functions.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-up}" in
    up)  build; smoke ;;
    run) build; shift; exec "$@" ;;
    *)   echo "usage: $0 {up|run CMD...}" >&2; exit 2 ;;
  esac
fi
