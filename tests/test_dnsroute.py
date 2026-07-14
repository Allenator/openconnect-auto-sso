"""Tests for src/dnsroute.py (the loopback DNS-routing proxy).

Pure-logic tests: subprocess.run (/sbin/route) is always patched, so no real routes
are touched and no root is needed. The forwarding sockets (which bind port 53) are
NOT exercised here -- only the route-injection, cooldown/in-flight, and
servfail/silence logic, which is where the bugs live.
"""
import threading
import time
import types
from unittest import mock

import pytest

import dns.message
import dns.rcode
import dns.rrset

import dnsroute


@pytest.fixture(autouse=True)
def reset_state():
    """Reset dnsroute's module globals before each test so they don't contaminate."""
    dnsroute._SEEN.clear()
    dnsroute._FAILS.clear()
    dnsroute._INFLIGHT.clear()
    dnsroute._EVER_FORWARDED = False
    dnsroute._START = time.monotonic()
    dnsroute.DEV = "utun-test"
    dnsroute.EXCLUDES = set()
    dnsroute.DRY_RUN = False
    yield


@pytest.fixture(autouse=True)
def quiet_log(monkeypatch):
    monkeypatch.setattr(dnsroute, "log", lambda *a, **k: None)


def _run_ok(cmd, **kw):
    return types.SimpleNamespace(returncode=0, stderr="")


def _run_fail(cmd, **kw):
    return types.SimpleNamespace(returncode=1,
                                 stderr="route: writing to routing socket: not in table")


# --- add_route ---------------------------------------------------------------
def test_success_marks_seen_and_dedups():
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_ok) as run:
        dnsroute.add_route("203.0.113.10")
        dnsroute.add_route("203.0.113.10")   # second call must be a no-op
    assert run.call_count == 1
    assert "203.0.113.10" in dnsroute._SEEN


def test_ipv6_uses_inet6_route_command():
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_ok) as run:
        dnsroute.add_route("2001:db8::1")
    cmd = run.call_args[0][0]
    assert "-inet6" in cmd
    assert "2001:db8::1" in cmd
    assert "utun-test" in cmd


def test_file_exists_is_treated_as_success():
    def run(cmd, **kw):
        return types.SimpleNamespace(returncode=1, stderr="route: File exists")
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=run):
        dnsroute.add_route("203.0.113.11")
    assert "203.0.113.11" in dnsroute._SEEN
    assert "203.0.113.11" not in dnsroute._FAILS


def test_excluded_ip_is_never_routed():
    dnsroute.EXCLUDES = {"10.0.0.1"}
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_ok) as run:
        dnsroute.add_route("10.0.0.1")
    run.assert_not_called()
    assert "10.0.0.1" in dnsroute._SEEN   # marked so it isn't re-logged every lookup


def test_dry_run_does_not_fork():
    dnsroute.DRY_RUN = True
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_ok) as run:
        dnsroute.add_route("203.0.113.12")
    run.assert_not_called()
    assert "203.0.113.12" in dnsroute._SEEN


def test_failure_records_cooldown_and_blocks_immediate_refork():
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_fail) as run:
        dnsroute.add_route("203.0.113.13")     # fails -> records failure
        assert "203.0.113.13" in dnsroute._FAILS
        dnsroute.add_route("203.0.113.13")     # within cooldown -> no refork
    assert run.call_count == 1


def test_refork_allowed_after_cooldown_elapses():
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_fail) as run:
        dnsroute.add_route("203.0.113.14")
        # Rewind the recorded failure past the cooldown window.
        dnsroute._FAILS["203.0.113.14"] = time.monotonic() - dnsroute.RETRY_COOLDOWN - 1
        dnsroute.add_route("203.0.113.14")
    assert run.call_count == 2                  # never permanently gives up


def test_inflight_claim_prevents_concurrent_duplicate_fork():
    # Regression for the fork-storm: while one thread's /sbin/route is running, a
    # concurrent lookup for the SAME ip must not fork a second one. The cooldown alone
    # can't guarantee this (it's shorter than the 5s route timeout and is recorded only
    # after the call), so add_route claims the ip in _INFLIGHT before releasing the lock.
    started = threading.Event()
    release = threading.Event()
    calls = []

    def blocking_run(cmd, **kw):
        calls.append(cmd)
        started.set()
        release.wait(5)
        return types.SimpleNamespace(returncode=0, stderr="")

    with mock.patch.object(dnsroute.subprocess, "run", side_effect=blocking_run):
        t = threading.Thread(target=dnsroute.add_route, args=("203.0.113.15",))
        t.start()
        assert started.wait(5), "first add_route never entered subprocess.run"
        # Second concurrent call for the same ip while the first is still in flight.
        dnsroute.add_route("203.0.113.15")
        assert len(calls) == 1, "in-flight ip was forked a second time"
        release.set()
        t.join(5)
    assert "203.0.113.15" in dnsroute._SEEN
    assert "203.0.113.15" not in dnsroute._INFLIGHT   # released after completion


def test_inflight_released_even_when_route_raises():
    def boom(cmd, **kw):
        raise OSError("route blew up")
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=boom):
        dnsroute.add_route("203.0.113.16")
    assert "203.0.113.16" not in dnsroute._INFLIGHT   # finally: released
    assert "203.0.113.16" in dnsroute._FAILS          # and recorded as failed


# --- C1: bogus-scope filter (loopback/link-local/multicast/unspecified) -------
# Mutation-meaningful: each of these forks /sbin/route today if the _is_bogus_scope
# guard in add_route is removed, so run.assert_not_called() pins the filter.
@pytest.mark.parametrize("bogus", [
    "127.0.0.2",   # loopback v4 -- the split-horizon blackhole that motivated C1
    "169.254.1.1", # link-local v4
    "224.0.0.1",   # multicast v4
    "0.0.0.0",     # unspecified v4
    "::1",         # loopback v6
    "fe80::1",     # link-local v6
    "ff02::1",     # multicast v6
    "::",          # unspecified v6
])
def test_bogus_scope_ip_is_not_routed(bogus):
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_ok) as run:
        dnsroute.add_route(bogus)
    run.assert_not_called()                  # never forks /sbin/route
    assert bogus in dnsroute._SEEN           # marked so it isn't re-logged every lookup
    assert bogus not in dnsroute._INFLIGHT   # in-flight claim released in finally


@pytest.mark.parametrize("routable", [
    "10.1.2.3",    # private RFC1918 -- must still route
    "104.16.1.1",  # public          -- must still route (routing is NOT private-only)
])
def test_routable_ip_is_still_routed(routable):
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_ok) as run:
        dnsroute.add_route(routable)
    run.assert_called_once()
    assert routable in dnsroute._SEEN


def test_unparseable_answer_ip_is_not_routed():
    # add_route parses untrusted DNS answers as root; a non-IP string must be dropped
    # (treated as bogus), never handed to /sbin/route.
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_ok) as run:
        dnsroute.add_route("not-an-ip")
    run.assert_not_called()


# --- inject_routes -----------------------------------------------------------
def _resp_with(name, rrtype, *values):
    q = dns.message.make_query(name, rrtype)
    resp = dns.message.make_response(q)
    resp.answer.append(dns.rrset.from_text(name + ".", 300, "IN", rrtype, *values))
    return resp.to_wire()


def test_a_records_each_get_a_route():
    wire = _resp_with("host.corp", "A", "10.1.2.3", "10.1.2.4")
    with mock.patch.object(dnsroute, "add_route") as add:
        dnsroute.inject_routes(wire)
    routed = {c.args[0] for c in add.call_args_list}
    assert routed == {"10.1.2.3", "10.1.2.4"}


def test_aaaa_records_get_routes():
    wire = _resp_with("host.corp", "AAAA", "2001:db8::9")
    with mock.patch.object(dnsroute, "add_route") as add:
        dnsroute.inject_routes(wire)
    assert {c.args[0] for c in add.call_args_list} == {"2001:db8::9"}


def test_malformed_wire_is_ignored():
    with mock.patch.object(dnsroute, "add_route") as add:
        dnsroute.inject_routes(b"\x00\x01not-a-dns-message")
    add.assert_not_called()


@pytest.mark.skipif(dnsroute._SVCB_PARAM is None, reason="dnspython lacks SVCB param keys")
def test_svcb_hints_are_routed():
    wire = _resp_with("h.corp", "HTTPS",
                      "1 . ipv4hint=203.0.113.5 ipv6hint=2001:db8::5")
    with mock.patch.object(dnsroute, "add_route") as add:
        dnsroute.inject_routes(wire)
    routed = {c.args[0] for c in add.call_args_list}
    assert "203.0.113.5" in routed
    assert "2001:db8::5" in routed


@pytest.mark.skipif(dnsroute._SVCB_PARAM is None, reason="dnspython lacks SVCB param keys")
def test_svcb_hint_bogus_scope_filtered_end_to_end():
    # The scope filter lives in add_route (the single choke point), so an SVCB
    # ipv4hint pointing at loopback is dropped end-to-end just like an A record,
    # while a sibling routable hint on the same record still gets its route. This
    # exercises the real add_route (subprocess mocked), not a mocked add_route.
    wire = _resp_with("h.corp", "HTTPS", "1 . ipv4hint=127.0.0.2,10.9.8.7")
    with mock.patch.object(dnsroute.subprocess, "run", side_effect=_run_ok) as run:
        dnsroute.inject_routes(wire)
    flat = [" ".join(c.args[0]) for c in run.call_args_list]
    assert run.call_count == 1                        # only the routable hint forked route
    assert any("10.9.8.7" in f for f in flat)
    assert not any("127.0.0.2" in f for f in flat)    # loopback hint never routed


# --- servfail_or_silence -----------------------------------------------------
def _query():
    return dns.message.make_query("x.corp", "A").to_wire()


def test_silent_during_grace_before_any_forward():
    dnsroute._EVER_FORWARDED = False
    dnsroute._START = time.monotonic()
    assert dnsroute.servfail_or_silence(_query()) is None


def test_servfail_after_grace_window():
    dnsroute._EVER_FORWARDED = False
    dnsroute._START = time.monotonic() - dnsroute.GRACE_SECONDS - 1
    out = dnsroute.servfail_or_silence(_query())
    assert out is not None
    assert dns.message.from_wire(out).rcode() == dns.rcode.SERVFAIL


def test_servfail_immediately_once_forwarded():
    # Even inside the grace window, once we've proven the VPN DNS works we fail fast
    # instead of hanging the client with silence.
    dnsroute._START = time.monotonic()
    dnsroute._mark_forwarded()
    assert dnsroute._EVER_FORWARDED
    assert dnsroute.servfail_or_silence(_query()) is not None
