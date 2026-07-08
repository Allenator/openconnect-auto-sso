#!/usr/bin/env python3
"""dnsroute.py -- a tiny loopback DNS proxy that routes answered IPs via the VPN.

Started as root by the vpnc-slice wrapper on connect. macOS `/etc/resolver/<name>`
files point selected domains at `127.0.0.1:<port>`; this proxy forwards each query
to the VPN's own DNS server(s) and, for every A/AAAA answer, adds a host route out
the tunnel device -- so a name scoped to the VPN is not just resolved via the VPN
but actually *reachable* over it, even when it load-balances across rotating IPs.

    dnsroute.py --upstream "IP[,| IP]..." --dev TUNDEV --port P \
                [--exclude "IP..."] [--dry-run]

It is deliberately minimal and loopback-only: it binds 127.0.0.1:<port> (UDP and
TCP), forwards the raw query bytes to the first responsive upstream (port 53),
returns the response verbatim, and only *reads* the response to inject /32|/128
interface routes -- never the default route, and never an --exclude'd IP (the
wrapper passes the VPN gateway there: routing the tunnel's own transport peer
through the tunnel would loop it). Routes are installed *before* the DNS answer
is returned, so even the client's first packet takes the tunnel. Injected interface routes vanish with
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
import dns.rcode
import dns.rdatatype

try:  # SVCB/HTTPS (type 64/65) ipv4hint/ipv6hint param keys; absent on old dnspython
    from dns.rdtypes.svcbbase import ParamKey as _SVCB_PARAM
except Exception:
    _SVCB_PARAM = None

# --- config (set in main; module globals keep the handlers minimal) ----------
UPSTREAMS = []      # list of upstream DNS server IPs (tried in order)
DEV = ""            # tunnel device to route answered IPs through (e.g. utun4)
EXCLUDES = set()    # IPs never to route (the VPN gateway -- routing it would loop the tunnel)
DRY_RUN = False     # log route commands instead of running them
TIMEOUT = 3.0       # per-upstream forward timeout (seconds)
WATCHDOG_INTERVAL = 15.0

_SEEN = set()                 # IPs we've already added a route for (or given up on)
_FAILS = {}                   # ip -> consecutive failed route-add attempts
_SEEN_LOCK = threading.Lock()
MAX_ROUTE_ATTEMPTS = 3        # after this many failures, stop retrying an IP


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
# The reply drives root route injection, so it must be genuinely the answer to
# our query: connect() the socket (the kernel then drops datagrams from any other
# source) and require the response transaction ID to match the query's. A fresh
# ephemeral socket per query means there's no cross-query contamination either.
def forward_udp(query):
    """Send a bare DNS query to the first responsive upstream; return its reply."""
    qid = query[:2]
    for up in UPSTREAMS:
        try:
            with socket.socket(_family(up), socket.SOCK_DGRAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((up, 53))
                s.send(query)
                resp = s.recv(65535)
                if resp[:2] == qid:
                    return resp
                # txid mismatch: a stray/duplicate packet -- ignore, try next.
        except OSError:
            continue
    return None


def forward_tcp(raw):
    """Forward a 2-byte-length-prefixed DNS query over TCP; return the reply."""
    qid = raw[2:4]
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
                if body is None or body[:2] != qid:
                    continue
                return lp + body
        except OSError:
            continue
    return None


def servfail(query):
    """Build a SERVFAIL reply to QUERY so the client fails fast (vs. our silence)."""
    try:
        resp = dns.message.make_response(dns.message.from_wire(query))
        resp.set_rcode(dns.rcode.SERVFAIL)
        return resp.to_wire()
    except Exception:
        return None


# --- route injection ---------------------------------------------------------
def _mark_seen(ip):
    with _SEEN_LOCK:
        _SEEN.add(ip)


def _note_failure(ip):
    """Record a failed route add; give up (return True) after MAX_ROUTE_ATTEMPTS.

    Bounds retries so a permanently-unroutable answer IP doesn't re-fork /sbin/route
    on every single lookup (route injection runs before the reply, so an unbounded
    retry would delay every DNS answer for that name forever). Transient failures
    (tunnel not fully up yet) still get a few retries before we stop.
    """
    with _SEEN_LOCK:
        n = _FAILS.get(ip, 0) + 1
        _FAILS[ip] = n
        if n >= MAX_ROUTE_ATTEMPTS:
            _SEEN.add(ip)     # give up: treat as handled so we stop retrying
            return True
    return False


def add_route(ip):
    with _SEEN_LOCK:
        if ip in _SEEN:
            return
    if ip in EXCLUDES:
        # Record it so we don't re-log the exclusion on every lookup.
        _mark_seen(ip)
        log("not routing %s (excluded: the VPN gateway/transport)" % ip)
        return
    if _family(ip) == socket.AF_INET6:
        cmd = ["/sbin/route", "-n", "add", "-inet6", ip, "-interface", DEV]
    else:
        cmd = ["/sbin/route", "-n", "add", "-host", ip, "-interface", DEV]
    if DRY_RUN:
        _mark_seen(ip)
        log(" ".join(cmd))
        return
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as e:
        # A transient failure (e.g. tunnel not fully up yet) should retry on the
        # next lookup, but bound it so a permanent failure doesn't retry forever.
        _tail = "giving up" if _note_failure(ip) else "will retry"
        log("route add failed for %s: %s (%s)" % (ip, e, _tail))
        return
    if res.returncode == 0 or "File exists" in (res.stderr or ""):
        _mark_seen(ip)
    else:
        _tail = "giving up" if _note_failure(ip) else "will retry"
        log("route add failed for %s: %s (%s)" % (ip, (res.stderr or "").strip(), _tail))


def _svcb_hint_ips(item):
    """Yield the ipv4hint/ipv6hint addresses of an SVCB/HTTPS record, if any."""
    if _SVCB_PARAM is None:
        return
    try:
        params = item.params
    except Exception:
        return
    for key in (_SVCB_PARAM.IPV4HINT, _SVCB_PARAM.IPV6HINT):
        hint = params.get(key)
        if not hint:
            continue
        for addr in getattr(hint, "addresses", ()):
            yield str(addr)


def inject_routes(wire):
    """Read-only parse of a DNS reply; add a host route per answer IP.

    Covers A/AAAA plus the ipv4hint/ipv6hint addresses inside HTTPS/SVCB (type
    64/65) records -- a client using an SVCB hint (ECH / HappyEyeballs) would
    otherwise reach a proxied name over the default interface, not the tunnel.
    """
    try:
        msg = dns.message.from_wire(wire)
    except Exception:
        return
    for rrset in msg.answer:
        for item in rrset:
            # Never let a single odd record abort injection -- this runs BEFORE the
            # reply is sent to the client, so an exception here would drop the answer.
            try:
                if item.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    add_route(item.address)
                elif item.rdtype in (dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
                    for ip in _svcb_hint_ips(item):
                        add_route(ip)
            except Exception as e:
                log("skipping unroutable answer record: %s" % e)


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
        if not resp:
            # All upstreams down: reply SERVFAIL so the client fails fast instead
            # of hanging and retrying against our silence.
            resp = servfail(data)
            if resp:
                try:
                    sock.sendto(resp, self.client_address)
                except OSError:
                    pass
            return
        # Routes go in BEFORE the answer is returned, so the client's very
        # first packet to a fresh IP already flows through the tunnel
        # (answer-then-route would let it race out the default interface).
        inject_routes(resp)
        try:
            sock.sendto(resp, self.client_address)
        except OSError:
            pass


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
        if not resp:
            # All upstreams down: SERVFAIL (length-prefixed) so the client fails fast.
            sf = servfail(query)
            if sf:
                try:
                    sock.sendall(struct.pack("!H", len(sf)) + sf)
                except OSError:
                    pass
            return
        # Same ordering as UDP: route first, then answer.
        if len(resp) >= 2:
            (rlen,) = struct.unpack("!H", resp[:2])
            inject_routes(resp[2:2 + rlen])
        try:
            sock.sendall(resp)
        except OSError:
            pass


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
    global UPSTREAMS, DEV, DRY_RUN, EXCLUDES
    ap = argparse.ArgumentParser(description="loopback DNS proxy that routes answers via the VPN")
    ap.add_argument("--upstream", required=True,
                    help="VPN DNS server IP(s), separated by commas or whitespace "
                         "(the wrapper passes INTERNAL_IP4_DNS verbatim)")
    ap.add_argument("--dev", required=True, help="tunnel device (e.g. utun4)")
    ap.add_argument("--port", required=True, type=int, help="loopback port to listen on")
    ap.add_argument("--exclude", default="",
                    help="IP(s) never to route via the tunnel (the VPN gateway); "
                         "comma/whitespace separated, may be empty")
    ap.add_argument("--ready-file", default="",
                    help="create this file once both sockets are bound (a readiness "
                         "signal the wrapper waits for before wiring /etc/resolver)")
    ap.add_argument("--dry-run", action="store_true",
                    help="log route commands instead of running them")
    args = ap.parse_args(argv[1:])

    UPSTREAMS = [x for x in re.split(r"[,\s]+", args.upstream.strip()) if x]
    DEV = args.dev
    port = args.port
    EXCLUDES = {x for x in re.split(r"[,\s]+", args.exclude.strip()) if x}
    DRY_RUN = args.dry_run
    if not UPSTREAMS:
        sys.stderr.write("dnsroute: no upstream given\n")
        return 2

    signal.signal(signal.SIGTERM, _on_term)

    udp = _ThreadingUDPServer(("127.0.0.1", port), UDPHandler)
    tcp = _ThreadingTCPServer(("127.0.0.1", port), TCPHandler)
    log("listening on 127.0.0.1:%d, upstream=%s, dev=%s%s%s"
        % (port, ",".join(UPSTREAMS), DEV,
           ", exclude=" + ",".join(sorted(EXCLUDES)) if EXCLUDES else "",
           " (dry-run)" if DRY_RUN else ""))

    threading.Thread(target=udp.serve_forever, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    # Both sockets are now bound (and listening); signal readiness so the wrapper
    # only points /etc/resolver at us after the port is actually up.
    if args.ready_file:
        try:
            with open(args.ready_file, "w") as fh:
                fh.write("ready\n")
        except OSError as e:
            log("could not write ready-file %s: %s" % (args.ready_file, e))
    try:
        tcp.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
