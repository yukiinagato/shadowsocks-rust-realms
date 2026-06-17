"""Wire-faithful reference codec for Hysteria Realms primitives.

Mirrors apernet/hysteria extras/realm/punch.go and stun.go exactly, so the Rust
implementation can be unit-tested to produce byte-identical output.
Pure stdlib.
"""
import hashlib
import os
import secrets
import socket
import struct

# ---------------------------------------------------------------- punch packets
PUNCH_MAGIC = b"HYRLMv1\x00"          # 8 bytes
PUNCH_SALT_LEN = 8
PUNCH_HEADER_LEN = 25                  # 8 magic + 1 type + 16 nonce
PUNCH_MIN_WIRE = PUNCH_SALT_LEN + PUNCH_HEADER_LEN          # 33
MAX_PUNCH_PADDING = 1024
PUNCH_MAX_WIRE = PUNCH_MIN_WIRE + MAX_PUNCH_PADDING         # 1057
HELLO = 0x01
ACK = 0x02
NONCE_SIZE = 16
OBFS_KEY_SIZE = 32


def _xor(buf: bytearray, obfs_key: bytes, salt: bytes) -> None:
    mask = hashlib.sha256(obfs_key + salt).digest()   # 32 bytes
    for i in range(len(buf)):
        buf[i] ^= mask[i % len(mask)]


def encode_punch(ptype: int, nonce: bytes, obfs_key: bytes, pad_len=None) -> bytes:
    assert ptype in (HELLO, ACK)
    assert len(nonce) == NONCE_SIZE and len(obfs_key) == OBFS_KEY_SIZE
    if pad_len is None:
        pad_len = secrets.randbelow(MAX_PUNCH_PADDING + 1)
    plain = bytearray(PUNCH_HEADER_LEN + pad_len)
    plain[0:8] = PUNCH_MAGIC
    plain[8] = ptype
    plain[9:25] = nonce
    if pad_len:
        plain[25:] = os.urandom(pad_len)
    salt = os.urandom(PUNCH_SALT_LEN)
    body = bytearray(plain)
    _xor(body, obfs_key, salt)
    return salt + bytes(body)


def decode_punch(packet: bytes, nonce: bytes, obfs_key: bytes):
    """Return ('hello'|'ack', pad_len) or raise ValueError."""
    if not (PUNCH_MIN_WIRE <= len(packet) <= PUNCH_MAX_WIRE):
        raise ValueError("bad length")
    salt, body = packet[:PUNCH_SALT_LEN], bytearray(packet[PUNCH_SALT_LEN:])
    _xor(body, obfs_key, salt)
    if bytes(body[0:8]) != PUNCH_MAGIC:
        raise ValueError("bad magic")
    ptype = body[8]
    if ptype not in (HELLO, ACK):
        raise ValueError("bad type")
    if bytes(body[9:25]) != nonce:
        raise ValueError("nonce mismatch")
    return ("hello" if ptype == HELLO else "ack", len(body) - PUNCH_HEADER_LEN)


# ----------------------------------------------------------------------- STUN
STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020


def stun_binding_request() -> tuple[bytes, bytes]:
    txid = os.urandom(12)
    msg = struct.pack(">HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE) + txid
    return msg, txid


def _xor_addr_attr(txid: bytes, ip: str, port: int) -> bytes:
    fam = 0x01
    xport = port ^ (STUN_MAGIC_COOKIE >> 16)
    ipb = socket.inet_aton(ip)
    cookie = struct.pack(">I", STUN_MAGIC_COOKIE)
    xip = bytes(a ^ b for a, b in zip(ipb, cookie))
    val = struct.pack(">BBH", 0, fam, xport) + xip
    return struct.pack(">HH", ATTR_XOR_MAPPED_ADDRESS, len(val)) + val


def stun_binding_response(txid: bytes, ip: str, port: int) -> bytes:
    attr = _xor_addr_attr(txid, ip, port)
    return struct.pack(">HHI", STUN_BINDING_SUCCESS, len(attr), STUN_MAGIC_COOKIE) + txid + attr


def parse_stun_response(packet: bytes):
    """Return (ip, port) from a Binding success, or None."""
    if len(packet) < 20:
        return None
    mtype, mlen, cookie = struct.unpack(">HHI", packet[:8])
    txid = packet[8:20]
    if mtype != STUN_BINDING_SUCCESS or cookie != STUN_MAGIC_COOKIE:
        return None
    off = 20
    end = 20 + mlen
    while off + 4 <= end:
        atype, alen = struct.unpack(">HH", packet[off:off + 4])
        aval = packet[off + 4:off + 4 + alen]
        off += 4 + alen + ((4 - alen % 4) % 4)
        if atype == ATTR_XOR_MAPPED_ADDRESS and len(aval) >= 8:
            xport = struct.unpack(">H", aval[2:4])[0] ^ (STUN_MAGIC_COOKIE >> 16)
            cookie = struct.pack(">I", STUN_MAGIC_COOKIE)
            ip = socket.inet_ntoa(bytes(a ^ b for a, b in zip(aval[4:8], cookie)))
            return ip, xport
        if atype == ATTR_MAPPED_ADDRESS and len(aval) >= 8:
            port = struct.unpack(">H", aval[2:4])[0]
            return socket.inet_ntoa(aval[4:8]), port
    return None


if __name__ == "__main__":
    # self-test: round-trip + byte-layout assertions
    nonce = bytes(range(16))
    obfs = bytes(range(32))
    pkt = encode_punch(HELLO, nonce, obfs, pad_len=10)
    assert len(pkt) == PUNCH_MIN_WIRE + 10
    assert decode_punch(pkt, nonce, obfs) == ("hello", 10)
    # tamper magic -> reject
    bad = bytearray(pkt); bad[8] ^= 0xFF
    try:
        decode_punch(bytes(bad), nonce, obfs); raise SystemExit("should have failed")
    except ValueError:
        pass
    req, txid = stun_binding_request()
    resp = stun_binding_response(txid, "198.51.100.20", 41234)
    assert parse_stun_response(resp) == ("198.51.100.20", 41234)
    print("hyrlm.py self-test OK")
