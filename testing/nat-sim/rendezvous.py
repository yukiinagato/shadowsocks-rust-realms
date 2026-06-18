#!/usr/bin/env python3
"""Faithful-subset rendezvous server for the testbed.

Implements the hysteria-realm-server endpoint contract (paths, JSON shapes,
bearer auth, the connect<->connects nonce handshake). SSE is simplified to a
one-event long-poll on GET /v1/{realm}/events (enough to introduce peers and to
exercise a Rust rendezvous client's request/response handling).

Pure stdlib, threaded. NOT for production — testbed only.
"""
import collections
import json
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "test-token"

realms = {}           # name -> {session_id, addresses, event_q, pending}
realms_lock = threading.Lock()


class Realm:
    def __init__(self, addresses):
        self.session_id = uuid.uuid4().hex
        self.addresses = addresses
        self.events = collections.deque()   # queued punch events (multi-client safe)
        self.event_cv = threading.Condition()
        self.attempts = {}           # nonce -> {addresses, cv, done}


def _json(h, code, obj):
    body = json.dumps(obj).encode()
    h.send_response(code)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


def _err(h, code, c, msg=""):
    _json(h, code, {"error": c, "message": msg or c})


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _auth_token(self):
        return self.headers.get("Authorization", "") == f"Bearer {TOKEN}"

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def _parts(self):
        return [p for p in self.path.split("?")[0].split("/") if p]

    # ---- POST: register / connect / connects / heartbeat ----
    def do_POST(self):
        p = self._parts()                      # ["v1", realm, ...]
        if len(p) < 2 or p[0] != "v1":
            return _err(self, 404, "not_found")
        realm = p[1]

        if len(p) == 2:                        # POST /v1/{realm}  register
            if not self._auth_token():
                return _err(self, 401, "invalid_token")
            body = self._body()
            with realms_lock:
                if realm in realms:
                    return _err(self, 409, "realm_taken")
                r = Realm(body.get("addresses", []))
                realms[realm] = r
            return _json(self, 200, {"session_id": r.session_id, "ttl": 60})

        r = realms.get(realm)
        if r is None:
            return _err(self, 404, "realm_not_found")

        if len(p) == 3 and p[2] == "connect":  # client asks to connect
            if not self._auth_token():
                return _err(self, 401, "invalid_token")
            body = self._body()
            nonce, obfs = body["nonce"], body["obfs"]
            attempt = {"addresses": None, "cv": threading.Condition(), "done": False}
            r.attempts[nonce] = attempt
            with r.event_cv:                    # queue event for server's events poll
                r.events.append({"addresses": body["addresses"], "nonce": nonce, "obfs": obfs})
                r.event_cv.notify_all()
            with attempt["cv"]:                 # block <=10s for server's fresh addrs
                if not attempt["done"]:
                    attempt["cv"].wait(timeout=10)
            addrs = attempt["addresses"] if attempt["done"] else r.addresses
            r.attempts.pop(nonce, None)
            return _json(self, 200, {"addresses": addrs, "nonce": nonce, "obfs": obfs})

        if len(p) == 4 and p[2] == "connects":  # server posts fresh addrs
            nonce = p[3]
            a = r.attempts.get(nonce)
            if a is None:
                return _err(self, 404, "attempt_not_found")
            body = self._body()
            with a["cv"]:
                a["addresses"] = body.get("addresses", [])
                a["done"] = True
                a["cv"].notify_all()
            self.send_response(204); self.end_headers(); return

        if len(p) == 3 and p[2] == "heartbeat":
            return _json(self, 200, {"ttl": 60})
        return _err(self, 404, "not_found")

    # ---- GET /v1/{realm}/events : one-event long-poll (simplified SSE) ----
    def do_GET(self):
        p = self._parts()
        if len(p) == 3 and p[0] == "v1" and p[2] == "events":
            r = realms.get(p[1])
            if r is None:
                return _err(self, 404, "realm_not_found")
            with r.event_cv:
                if not r.events:
                    r.event_cv.wait(timeout=30)
                ev = r.events.popleft() if r.events else None
            if ev is None:
                return _json(self, 200, {"event": "heartbeat_ack", "ttl": 60})
            return _json(self, 200, {"event": "punch", **ev})
        return _err(self, 404, "not_found")

    def do_DELETE(self):
        p = self._parts()
        if len(p) == 2 and p[0] == "v1":
            realms.pop(p[1], None)
            self.send_response(204); self.end_headers(); return
        return _err(self, 404, "not_found")


if __name__ == "__main__":
    ip, port = sys.argv[1], int(sys.argv[2])
    srv = ThreadingHTTPServer((ip, port), Handler)
    print(f"[rendezvous] http://{ip}:{port}", flush=True)
    srv.serve_forever()
