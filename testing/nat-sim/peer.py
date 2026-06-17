#!/usr/bin/env python3
"""A Realms peer: STUN-discovers its public address on a single UDP socket,
uses the rendezvous to exchange addresses with the other side, performs the
HYRLMv1 hole punch, then exchanges an application datagram to prove the hole is
open. The same UDP socket is used for STUN, punch, and data (port reuse), which
is exactly what the real implementation requires.

roles:
  server  -> registers realm, waits on events, punches toward the client
  client  -> connect to realm, punches toward the server
"""
import json
import os
import secrets
import socket
import sys
import time
import urllib.request

from hyrlm import (
    stun_binding_request, parse_stun_response,
    encode_punch, decode_punch, HELLO, ACK, PUNCH_MIN_WIRE, PUNCH_MAX_WIRE,
)

TOKEN = "test-token"

# The sandbox sets http(s)_proxy in the environment; inside the netns that proxy
# is unreachable. Talk to the rendezvous directly.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(role, *a):
    print(f"[{role}]", *a, flush=True)


def http(method, url, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with _OPENER.open(req, timeout=15) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None)


def stun_discover(sock, stun_addr, role):
    """Return public 'ip:port' for sock as seen by the STUN server."""
    req, txid = stun_binding_request()
    for _ in range(5):
        sock.sendto(req, stun_addr)
        sock.settimeout(1.0)
        try:
            while True:
                data, _ = sock.recvfrom(2048)
                res = parse_stun_response(data)
                if res:
                    ipp = f"{res[0]}:{res[1]}"
                    log(role, f"STUN public address = {ipp}")
                    return ipp
        except socket.timeout:
            continue
    raise RuntimeError("STUN discovery failed")


def punch(sock, peer_addrs, nonce, obfs, role, deadline=8.0):
    """Symmetric Hello/Ack punch. Returns the confirmed peer (ip,port)."""
    peers = [(h, int(p)) for h, p in (a.split(":") for a in peer_addrs)]
    nb, ob = bytes.fromhex(nonce), bytes.fromhex(obfs)
    hello = lambda: encode_punch(HELLO, nb, ob)
    ack = lambda: encode_punch(ACK, nb, ob)
    sock.settimeout(0.2)
    end = time.time() + deadline
    confirmed = None
    last_send = 0
    while time.time() < end and confirmed is None:
        now = time.time()
        if now - last_send > 0.25:                 # fire Hello at all candidates
            for pa in peers:
                try: sock.sendto(hello(), pa)
                except OSError: pass
            last_send = now
        try:
            data, src = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if not (PUNCH_MIN_WIRE <= len(data) <= PUNCH_MAX_WIRE):
            continue
        try:
            kind, _ = decode_punch(data, nb, ob)
        except ValueError:
            continue
        if kind == "hello":
            sock.sendto(ack(), src)                 # answer with Ack
            log(role, f"got Hello from {src[0]}:{src[1]} -> sent Ack")
        elif kind == "ack":
            confirmed = src
            log(role, f"got Ack from {src[0]}:{src[1]} -> hole OPEN")
    if confirmed is None:
        raise RuntimeError("punch failed (likely symmetric NAT)")
    # keep sending a few Acks so the peer also confirms
    for _ in range(5):
        sock.sendto(ack(), confirmed)
        time.sleep(0.05)
    return confirmed


def run_server(realm_url_base, realm, stun_addr):
    role = "server"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", int(os.environ.get("REALM_LPORT", "0"))))  # Realms lport
    pub = stun_discover(sock, stun_addr, role)
    _, reg = http("POST", f"{realm_url_base}/v1/{realm}", {"addresses": [pub]}, token=TOKEN)
    log(role, f"registered realm '{realm}', session={reg['session_id'][:8]}…")
    # wait for a punch event
    while True:
        _, ev = http("GET", f"{realm_url_base}/v1/{realm}/events")
        if ev.get("event") == "punch":
            break
    log(role, f"punch event: client addrs={ev['addresses']}")
    pub2 = stun_discover(sock, stun_addr, role)     # fresh STUN
    http("POST", f"{realm_url_base}/v1/{realm}/connects/{ev['nonce']}", {"addresses": [pub2]})
    peer = punch(sock, ev["addresses"], ev["nonce"], ev["obfs"], role)
    # data exchange over the hole
    sock.settimeout(3.0)
    for _ in range(20):
        try:
            data, src = sock.recvfrom(2048)
            if data.startswith(b"PING"):
                log(role, f"recv {data!r} from {src} -> reply PONG")
                sock.sendto(b"PONG from server", src)
                log(role, "RESULT: data path confirmed ✓")
                return 0
        except socket.timeout:
            break
    log(role, "RESULT: no data received ✗")
    return 1


def run_client(realm_url_base, realm, stun_addr):
    role = "client"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", int(os.environ.get("REALM_LPORT", "0"))))  # Realms lport
    pub = stun_discover(sock, stun_addr, role)
    nonce = secrets.token_hex(16)
    obfs = secrets.token_hex(32)
    _, resp = http("POST", f"{realm_url_base}/v1/{realm}/connect",
                   {"addresses": [pub], "nonce": nonce, "obfs": obfs}, token=TOKEN)
    log(role, f"rendezvous returned server addrs={resp['addresses']}")
    peer = punch(sock, resp["addresses"], nonce, obfs, role)
    # send application data through the punched hole
    for _ in range(10):
        sock.sendto(b"PING from client", peer)
        sock.settimeout(0.5)
        try:
            data, src = sock.recvfrom(2048)
            if data.startswith(b"PONG"):
                log(role, f"recv {data!r} from {src}")
                log(role, "RESULT: round-trip through double-NAT confirmed ✓")
                return 0
        except socket.timeout:
            continue
    log(role, "RESULT: no reply ✗")
    return 1


if __name__ == "__main__":
    role = sys.argv[1]
    base = sys.argv[2]                  # http://198.51.100.1:8080
    realm = sys.argv[3]
    stun_host, stun_port = sys.argv[4].split(":")
    stun_addr = (stun_host, int(stun_port))
    if role == "server":
        sys.exit(run_server(base, realm, stun_addr))
    else:
        sys.exit(run_client(base, realm, stun_addr))
