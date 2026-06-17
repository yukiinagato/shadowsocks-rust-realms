import socket, sys, time, os
from hyrlm import stun_binding_request, parse_stun_response, encode_punch, decode_punch, HELLO, ACK

role = sys.argv[1]; myfile = sys.argv[2]; peerfile = sys.argv[3]
nonce = bytes.fromhex("00112233445566778899aabbccddeeff")
obfs = bytes(range(32))

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 0))
# robust STUN discovery
pub = None
for _ in range(10):
    req, _ = stun_binding_request(); s.sendto(req, ("198.51.100.1", 3478)); s.settimeout(0.5)
    try:
        d, _ = s.recvfrom(2048); r = parse_stun_response(d)
        if r: pub = r; break
    except socket.timeout: pass
print(f"[{role}] pub={pub}", flush=True)
open(myfile, "w").write(f"{pub[0]}:{pub[1]}")
# wait for peer's pub
peer = None
for _ in range(50):
    if os.path.exists(peerfile):
        txt = open(peerfile).read().strip()
        if txt: h, p = txt.split(":"); peer = (h, int(p)); break
    time.sleep(0.1)
print(f"[{role}] peer={peer}", flush=True)
# punch
s.settimeout(0.2); end = time.time() + 6; ok = False; last = 0
while time.time() < end:
    if time.time() - last > 0.25:
        s.sendto(encode_punch(HELLO, nonce, obfs), peer); last = time.time()
    try:
        d, src = s.recvfrom(2048)
    except socket.timeout:
        continue
    try:
        kind, _ = decode_punch(d, nonce, obfs)
    except ValueError:
        continue
    if kind == "hello":
        s.sendto(encode_punch(ACK, nonce, obfs), src)
        print(f"[{role}] HELLO<-{src} ack-sent", flush=True)
    else:
        print(f"[{role}] ACK<-{src} HOLE-OPEN", flush=True); ok = True; break
print(f"[{role}] RESULT={'OPEN' if ok else 'FAIL'}", flush=True)
sys.exit(0 if ok else 1)
