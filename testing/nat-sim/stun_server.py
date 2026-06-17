#!/usr/bin/env python3
"""Minimal RFC 5389 STUN Binding responder (UDP). Replies with XOR-MAPPED-ADDRESS
of the source as seen on the wire — i.e. the NAT-translated public address."""
import socket
import sys
from hyrlm import stun_binding_response, STUN_BINDING_REQUEST
import struct


def main(bind_ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, int(port)))
    print(f"[stun] listening on {bind_ip}:{port}", flush=True)
    while True:
        data, addr = s.recvfrom(2048)
        if len(data) < 20:
            continue
        mtype = struct.unpack(">H", data[:2])[0]
        if mtype != STUN_BINDING_REQUEST:
            continue
        txid = data[8:20]
        # addr is the source as seen here = public (post-NAT) ip:port
        s.sendto(stun_binding_response(txid, addr[0], addr[1]), addr)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
