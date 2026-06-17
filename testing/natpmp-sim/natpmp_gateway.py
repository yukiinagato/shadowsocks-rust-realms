#!/usr/bin/env python3
"""A real, minimal NAT-PMP (RFC 6886) gateway.

Answers external-address and TCP/UDP map requests AND installs **real iptables
DNAT** rules in its network namespace — exactly what OpenWrt's miniupnpd does for
a host that asks for an inbound port, just without the VM. Testbed only.

argv: <listen_ip> <wan_ip>
"""
import socket
import struct
import subprocess
import sys
import time

LISTEN_IP = sys.argv[1]
WAN_IP = sys.argv[2]
PORT = 5351
START = time.time()


def epoch():
    return int(time.time() - START) & 0xFFFFFFFF


def iptables(*args):
    subprocess.run(["iptables", *args], check=False)


def dnat(action, proto, ext_port, client_ip, int_port):
    # action is "-A" (install) or "-D" (remove)
    iptables("-t", "nat", action, "PREROUTING", "-p", proto, "-d", WAN_IP,
             "--dport", str(ext_port), "-j", "DNAT",
             "--to-destination", f"{client_ip}:{int_port}")
    iptables(action, "FORWARD", "-p", proto, "-d", client_ip,
             "--dport", str(int_port), "-j", "ACCEPT")


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_IP, PORT))
    print(f"[natpmp] gateway on {LISTEN_IP}:{PORT}, wan={WAN_IP}", flush=True)
    while True:
        data, addr = s.recvfrom(64)
        client_ip = addr[0]
        if len(data) < 2 or data[0] != 0:
            continue
        op = data[1]
        if op == 0:  # external-address request
            resp = struct.pack(">BBHI", 0, 128, 0, epoch()) + socket.inet_aton(WAN_IP)
            s.sendto(resp, addr)
            print(f"[natpmp] external-address -> {WAN_IP}", flush=True)
        elif op in (1, 2) and len(data) >= 12:  # map UDP / TCP
            int_port, ext_port, lease = struct.unpack(">HHI", data[4:12])
            proto = "udp" if op == 1 else "tcp"
            if ext_port == 0:
                ext_port = int_port
            if lease == 0:
                dnat("-D", proto, ext_port, client_ip, int_port)
                print(f"[natpmp] unmap {proto} {WAN_IP}:{ext_port}", flush=True)
            else:
                dnat("-A", proto, ext_port, client_ip, int_port)
                print(f"[natpmp] map {proto} {WAN_IP}:{ext_port} -> {client_ip}:{int_port}",
                      flush=True)
            resp = struct.pack(">BBHIHHI", 0, 128 + op, 0, epoch(), int_port, ext_port, lease)
            s.sendto(resp, addr)


if __name__ == "__main__":
    main()
