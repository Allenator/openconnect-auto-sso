#!/usr/bin/env python3
"""dnsroute.py -- a tiny loopback DNS proxy that routes answered IPs via the VPN.

Started as root by the vpnc-slice wrapper on connect. macOS `/etc/resolver/<name>`
files point selected domains at `127.0.0.1:<port>`; this proxy forwards each query
to the VPN's own DNS server(s) and, for every A/AAAA answer, adds a host route out
the tunnel device -- so a name scoped to the VPN is not just resolved via the VPN
but actually *reachable* over it, even when it load-balances across rotating IPs.

    dnsroute.py --upstream "IP[,| IP]..." --dev TUNDEV --port P [--dry-run]

It is deliberately minimal and loopback-only: it binds 127.0.0.1:<port> (UDP and
TCP), forwards the raw query bytes to the first responsive upstream (port 53),
returns the response verbatim, and only *reads* the response to inject /32|/128
interface routes -- never the default route. Injected interface routes vanish with
the utun, so there is no route teardown; a watchdog exits when the device is gone,
and SIGTERM exits cleanly.
"""
import argparse
import os
import re
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

import dns.message
import dns.rdatatype

# --- config (set in main; module globals keep the handlers minimal) ----------
UPSTREAMS = []      # list of upstream DNS server IPs (tried in order)
DEV = ""            # tunnel device to route answered IPs through (e.g. utun4)
PORT = 0            # loopback port to listen on
DRY_RUN = False     # log route commands instead of running them
TIMEOUT = 3.0       # per-upstream forward timeout (seconds)
WATCHDOG_INTERVAL = 15.0

_SEEN = set()                 # IPs we've already added a route for
_SEEN_LOCK = threading.Lock()


def log(msg):
    sys.stderr.write("dnsroute: " + msg + "\n")
    sys.stderr.flush()


def _family(ip):
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# --- forwarding --------------------------------------------------------------
def forward_udp(query):
    """Send a bare DNS query to the first responsive upstream; return its reply."""
    for up in UPSTREAMS:
        try:
            with socket.socket(_family(up), socket.SOCK_DGRAM) as s:
                s.settimeout(TIMEOUT)
                s.sendto(query, (up, 53))
                resp, _ = s.recvfrom(65535)
                return resp
        except OSError:
            continue
    return None


def forward_tcp(raw):
    """Forward a 2-byte-length-prefixed DNS query over TCP; return the reply."""
    for up in UPSTREAMS:
        try:
            with socket.socket(_family(up), socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((up, 53))
                s.sendall(raw)
                lp = _recv_exact(s, 2)
                if lp is None:
                    continue
                (rlen,) = struct.unpack("!H", lp)
                body = _recv_exact(s, rlen)
                if body is None:
                    continue
                return lp + body
        except OSError:
            continue
    return None


# --- route injection ---------------------------------------------------------
def add_route(ip, inet6):
    with _SEEN_LOCK:
        if ip in _SEEN:
            return
        _SEEN.add(ip)
    if inet6:
        cmd = ["/sbin/route", "-n", "add", "-inet6", ip, "-interface", DEV]
    else:
        cmd = ["/sbin/route", "-n", "add", "-host", ip, "-interface", DEV]
    if DRY_RUN:
        log(" ".join(cmd))
        return
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        log("route add failed for %s: %s" % (ip, e))
        return
    if res.returncode != 0 and "File exists" not in (res.stderr or ""):
        log("route add failed for %s: %s" % (ip, (res.stderr or "").strip()))


def inject_routes(wire):
    """Read-only parse of a DNS reply; add a host route per A/AAAA answer IP."""
    try:
        msg = dns.message.from_wire(wire)
    except Exception:
        return
    for rrset in msg.answer:
        for item in rrset:
            if item.rdtype == dns.rdatatype.A:
                add_route(item.address, inet6=False)
            elif item.rdtype == dns.rdatatype.AAAA:
                add_route(item.address, inet6=True)


# --- servers -----------------------------------------------------------------
class _ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = 65535


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        resp = forward_udp(data)
        if resp:
            try:
                sock.sendto(resp, self.client_address)
            except OSError:
                pass
            inject_routes(resp)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        lp = _recv_exact(sock, 2)
        if lp is None:
            return
        (qlen,) = struct.unpack("!H", lp)
        query = _recv_exact(sock, qlen)
        if query is None:
            return
        resp = forward_tcp(lp + query)
        if resp:
            try:
                sock.sendall(resp)
            except OSError:
                pass
            if len(resp) >= 2:
                (rlen,) = struct.unpack("!H", resp[:2])
                inject_routes(resp[2:2 + rlen])


# --- lifecycle ---------------------------------------------------------------
def watchdog():
    """Exit when the tunnel device disappears (its routes are already gone)."""
    while True:
        time.sleep(WATCHDOG_INTERVAL)
        try:
            res = subprocess.run(["/sbin/ifconfig", DEV],
                                 capture_output=True)
        except OSError:
            continue
        if res.returncode != 0:
            log("device %s is gone; exiting" % DEV)
            os._exit(0)


def _on_term(signum, frame):
    os._exit(0)


def main(argv):
    global UPSTREAMS, DEV, PORT, DRY_RUN
    ap = argparse.ArgumentParser(description="loopback DNS proxy that routes answers via the VPN")
    ap.add_argument("--upstream", required=True,
                    help="VPN DNS server IP(s), separated by commas or whitespace "
                         "(the wrapper passes INTERNAL_IP4_DNS verbatim)")
    ap.add_argument("--dev", required=True, help="tunnel device (e.g. utun4)")
    ap.add_argument("--port", required=True, type=int, help="loopback port to listen on")
    ap.add_argument("--dry-run", action="store_true",
                    help="log route commands instead of running them")
    args = ap.parse_args(argv[1:])

    UPSTREAMS = [x for x in re.split(r"[,\s]+", args.upstream.strip()) if x]
    DEV = args.dev
    PORT = args.port
    DRY_RUN = args.dry_run
    if not UPSTREAMS:
        sys.stderr.write("dnsroute: no upstream given\n")
        return 2

    signal.signal(signal.SIGTERM, _on_term)

    udp = _ThreadingUDPServer(("127.0.0.1", PORT), UDPHandler)
    tcp = _ThreadingTCPServer(("127.0.0.1", PORT), TCPHandler)
    log("listening on 127.0.0.1:%d, upstream=%s, dev=%s%s"
        % (PORT, ",".join(UPSTREAMS), DEV, " (dry-run)" if DRY_RUN else ""))

    threading.Thread(target=udp.serve_forever, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    try:
        tcp.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
