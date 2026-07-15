"""Tests for the POSIX-sh components, driven from pytest by shelling out to `sh`.

The executable scripts are sourced with a test-only guard (OC_*_TEST=1) that stops before
their main body, so individual functions can be exercised in isolation; file-touching
helpers are pointed at a temp dir via RESOLVER_DIR. lib/common.sh is the exception: it is
constants + functions with no main body, so it is sourced directly with no guard, and its
TCP probe is stubbed via NC_BIN so nothing touches the network. vpn-teardown is run as a
real subprocess with a PATH-stubbed `pgrep` (never exercising its kill path, which would
signal real PIDs).

macOS-only: the scripts use BSD `stat -f`, /etc/resolver, and utun conventions.
"""
import os
import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="shell scripts target macOS (BSD stat -f, /etc/resolver)")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MARKER = "# openconnect-auto-sso"

# Source lines that load each script's functions with its main body guarded off.
SRC_VPNC = 'export OC_VPNC_SLICE_TEST=1; . "$OC_PROJ/bin/vpnc-slice"'
SRC_INSTALL = 'export OC_INSTALL_TEST=1; . "$OC_PROJ/install-autostart.sh"'
TEARDOWN = os.path.join(REPO, "libexec", "vpn-teardown")


def _sh(setup_source, body, extra_env=None):
    """Source `setup_source`, relax set -eu, then run `body`; return CompletedProcess."""
    env = dict(os.environ, OC_PROJ=REPO)
    if extra_env:
        env.update(extra_env)
    script = "%s\nset +eu\n%s\n" % (setup_source, body)
    # timeout so a loop-termination regression (e.g. a wait_for_server that never gives up)
    # FAILS the test instead of hanging the whole run forever.
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env,
                          timeout=30)


def _mk_resolver(path, port, marker=MARKER):
    path.write_text("%s\nnameserver 127.0.0.1\nport %s\n" % (marker, port))


# --- vpnc-slice: _proxy_domains (@server expansion + unsafe-domain filtering) ---
def test_proxy_domains_expands_at_server_and_filters_unsafe():
    # CISCO_SPLIT_DNS is comma-separated (openconnect's vpnc-script format).
    body = (
        '_names="@server"\n'
        'CISCO_SPLIT_DNS="ok.corp,../etc,evil;rm,.hidden,-dash,under_score.corp"\n'
        'CISCO_DEF_DOMAIN=""\n'
        '_proxy_domains\n'
        "printf '[%s]\\n' \"$_domains\"\n"
    )
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    # Only the safe labels survive; the shell-metachar / dotfile / leading-dash / ".."
    # ones are dropped before they could become a root-written /etc/resolver path.
    assert r.stdout.strip() == "[ ok.corp under_score.corp]"


def test_proxy_domains_literal_names_pass_through():
    body = (
        '_names="foo.example,bar.example"\n'
        'CISCO_SPLIT_DNS=""; CISCO_DEF_DOMAIN=""\n'
        '_proxy_domains\n'
        "printf '[%s]\\n' \"$_domains\"\n"
    )
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "[ foo.example bar.example]"


# --- vpnc-slice: _sweep_our_resolvers (regression for the shrinking-@server leak) ---
def test_sweep_keeplist_drops_only_removed_domains(tmp_path):
    _mk_resolver(tmp_path / "a.corp", 45353)
    _mk_resolver(tmp_path / "b.corp", 45353)
    _mk_resolver(tmp_path / "other.corp", 45353)     # ours, our port, NOT in keep-list
    _mk_resolver(tmp_path / "c.corp", 40000)         # ours, but a different proxy's port
    (tmp_path / "foreign.corp").write_text("nameserver 9.9.9.9\n")   # not ours (no marker)
    body = '_port=45353\n_sweep_our_resolvers " a.corp b.corp "\n'
    r = _sh(SRC_VPNC, body, extra_env={"RESOLVER_DIR": str(tmp_path)})
    assert r.returncode == 0, r.stderr
    remaining = {p.name for p in tmp_path.iterdir()}
    # other.corp is dropped (a reconnect no longer routes it); everything else survives.
    assert remaining == {"a.corp", "b.corp", "c.corp", "foreign.corp"}


def test_sweep_without_keeplist_removes_all_our_port(tmp_path):
    _mk_resolver(tmp_path / "a.corp", 45353)
    _mk_resolver(tmp_path / "b.corp", 45353)
    _mk_resolver(tmp_path / "c.corp", 40000)         # different port -> left intact
    (tmp_path / "foreign.corp").write_text("nameserver 9.9.9.9\n")
    body = '_port=45353\n_sweep_our_resolvers\n'
    r = _sh(SRC_VPNC, body, extra_env={"RESOLVER_DIR": str(tmp_path)})
    assert r.returncode == 0, r.stderr
    remaining = {p.name for p in tmp_path.iterdir()}
    assert remaining == {"c.corp", "foreign.corp"}


# --- vpnc-slice: proxy-state helpers (orphan reclaim / double-start refusal) ---
def test_proxy_pid_reads_first_line(tmp_path):
    pf = tmp_path / "proxy"
    pf.write_text("4242\n9999\n")   # line 1 = dnsroute PID, line 2 = openconnect PID
    r = _sh(SRC_VPNC, '_pidfile="%s"\n_proxy_pid\n' % pf)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "4242"      # NOT "4242 9999" -- only the dnsroute PID


def test_proxy_pid_empty_when_no_file(tmp_path):
    r = _sh(SRC_VPNC, '_pidfile="%s"\n[ -z "$(_proxy_pid)" ] && echo EMPTY\n' % (tmp_path / "nope"))
    assert r.returncode == 0, r.stderr
    assert "EMPTY" in r.stdout


def test_is_dnsroute_matches_real_dnsroute_not_others():
    # Spawn a real dnsroute in --dry-run (binds 127.0.0.1:<port>, no root, no routes) and
    # confirm _is_dnsroute matches its PID by command, and rejects an unrelated PID (guards
    # the root kill against PID reuse).
    proc = subprocess.Popen(
        [os.path.join(REPO, ".venv/bin/python"), os.path.join(REPO, "src/dnsroute.py"),
         "--upstream", "127.0.0.1", "--dev", "lo0", "--port", "45999", "--dry-run"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):     # wait until it's in ps with its full argv
            out = subprocess.run(["ps", "-p", str(proc.pid), "-o", "command="],
                                 capture_output=True, text=True).stdout
            if "dnsroute.py" in out:
                break
            time.sleep(0.1)
        r = _sh(SRC_VPNC, '_is_dnsroute %d && echo YES || echo NO\n' % proc.pid)
        assert r.stdout.strip() == "YES", (r.stderr, out)
        r2 = _sh(SRC_VPNC, '_is_dnsroute 1 && echo YES || echo NO\n')   # pid 1 = launchd
        assert r2.stdout.strip() == "NO"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# --- vpnc-slice: NC_BIN root-gate (off-root the override is still honored) -----------
def test_vpnc_slice_nonroot_honors_nc_bin_override(tmp_path):
    # Off the root path (the test runs as non-root), vpnc-slice must NOT pin NC_BIN, so
    # common.sh's server_reachable can still be stubbed for the wait_for_server tests. The
    # ROOT branch forces NC_BIN=/usr/bin/nc before sourcing common.sh, making the probe inert
    # regardless of a future root caller or a sudoers env_keep -- but that can't be unit-tested
    # without being root (same limitation as the PROJ/RESOLVER_DIR root-gate), so it's verified
    # by inspection. This test pins the complementary half: the seam survives off the root path.
    nc = tmp_path / "nc"
    nc.write_text("#!/bin/sh\nexit 0\n")
    nc.chmod(0o755)
    r = _sh(SRC_VPNC, 'printf "%s\\n" "$NC_BIN"\nserver_reachable host 443 && echo REACH\n',
            extra_env={"NC_BIN": str(nc)})
    assert r.returncode == 0, r.stderr
    assert str(nc) in r.stdout      # override survived (non-root branch didn't pin it)
    assert "REACH" in r.stdout      # and the stub was actually invoked by server_reachable


# --- install-autostart: dir_is_safe + verify_safe_ancestors (NOPASSWD-helper guard) ---
def test_dir_is_safe_rejects_user_owned(tmp_path):
    r = _sh(SRC_INSTALL, 'dir_is_safe "%s" && echo SAFE || echo UNSAFE' % tmp_path)
    assert r.stdout.strip() == "UNSAFE"


def test_dir_is_safe_accepts_root_system_dir():
    r = _sh(SRC_INSTALL, 'dir_is_safe /usr/bin && echo SAFE || echo UNSAFE')
    assert r.stdout.strip() == "SAFE"


def test_dir_is_safe_rejects_root_owned_symlink():
    # Regression: stat -f is lstat, so a symlinked component (mode l...) is rejected --
    # otherwise install -d would follow it to an unchecked target. /var is a real
    # root-owned symlink (uid 0, `lrwxr-xr-x` -> private/var), so it PASSES the uid==0
    # check and can only be rejected by the l*) branch -- which is exactly what must be
    # exercised. (A user-owned symlink would be rejected on ownership first, masking it.)
    r = _sh(SRC_INSTALL, 'dir_is_safe /var && echo SAFE || echo UNSAFE')
    assert r.stdout.strip() == "UNSAFE"


def test_verify_safe_ancestors_accepts_root_chain():
    # Every existing component of /usr/bin/<nonexistent> is a root-owned system dir.
    r = _sh(SRC_INSTALL, 'verify_safe_ancestors /usr/bin/zzz-nonexistent-leaf && echo OK || echo BAD')
    assert r.stdout.strip() == "OK"


def test_verify_safe_ancestors_rejects_unsafe_ancestor(tmp_path):
    # Regression: the walk must reject a chain with any user-writable/symlinked ancestor,
    # not just a hardcoded pair -- here the temp dir's own ancestors are user-owned.
    leaf = os.path.realpath(str(tmp_path)) + "/sub/leaf"
    r = _sh(SRC_INSTALL, 'verify_safe_ancestors "%s" && echo OK || echo BAD' % leaf)
    assert r.stdout.strip() == "BAD"
    assert "refusing to install" in r.stderr


# --- install-autostart: dir_no_other_write ($proj writability guard, D2) --------------
@pytest.mark.parametrize("mode,expect", [
    (0o700, "OK"), (0o755, "OK"), (0o750, "OK"), (0o705, "OK"),   # no group/other write
    (0o770, "NO"), (0o720, "NO"), (0o775, "NO"),                  # group-writable
    (0o702, "NO"), (0o706, "NO"), (0o707, "NO"),                  # other-writable
    (0o777, "NO"),                                                # both
])
def test_dir_no_other_write(tmp_path, mode, expect):
    # The connect script is run by the login agent as YOU and reaches root via NOPASSWD
    # openconnect, so a group/other-writable repo is a passwordless-root vector. Unlike
    # dir_is_safe this does NOT require root ownership (it's the user's own repo) -- only
    # that group/other can't write it.
    d = tmp_path / ("m%o" % mode)
    d.mkdir()
    d.chmod(mode)
    r = _sh(SRC_INSTALL, 'dir_no_other_write "%s" && echo OK || echo NO' % d)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == expect, oct(mode)


def test_dir_no_other_write_fails_closed_on_missing(tmp_path):
    # A path that can't be stat'd must fail closed (treated as unsafe), not accepted.
    r = _sh(SRC_INSTALL, 'dir_no_other_write "%s" && echo OK || echo NO' % (tmp_path / "nope"))
    assert r.stdout.strip() == "NO"


def test_do_install_refuses_group_or_other_writable_proj(tmp_path):
    # Integration: do_install must ABORT (before any sudo) when $proj is group/other-writable.
    # We override $proj/$connect after sourcing and point them at a world-writable fake repo
    # with an executable connect stub (so the earlier `-x` check passes). The writability
    # refusal is ordered before every privileged/mutating step, so this never touches sudo.
    proj = tmp_path / "shared-clone"
    (proj / "bin").mkdir(parents=True)
    connect = proj / "bin" / "openconnect-auto-sso"
    connect.write_text("#!/bin/sh\n:\n")
    connect.chmod(0o755)
    proj.chmod(0o777)                                    # world-writable repo root
    body = ('proj="%s"\nconnect="%s"\ndo_install\n') % (proj, connect)
    r = _sh(SRC_INSTALL, body)
    assert r.returncode != 0
    assert "group- or other-writable" in r.stderr
    assert "refusing to install" in r.stderr


def test_do_install_refuses_writable_connect_dir(tmp_path):
    # The bin/ dir holding $connect is checked too: a private repo root but a world-writable
    # bin/ (where the executed script lives) is still a plant-the-binary vector.
    proj = tmp_path / "repo"
    (proj / "bin").mkdir(parents=True)
    connect = proj / "bin" / "openconnect-auto-sso"
    connect.write_text("#!/bin/sh\n:\n")
    connect.chmod(0o755)
    proj.chmod(0o755)                                    # root private...
    (proj / "bin").chmod(0o777)                          # ...but bin/ world-writable
    body = ('proj="%s"\nconnect="%s"\ndo_install\n') % (proj, connect)
    r = _sh(SRC_INSTALL, body)
    assert r.returncode != 0
    assert "group- or other-writable" in r.stderr


# --- lib/common.sh: server_hostport + wait_for_server ---------------------------------
# common.sh is constants + functions with no main body, so it needs NO test seam --
# sourcing it directly is safe.
SRC_COMMON = '. "$OC_PROJ/lib/common.sh"'


@pytest.mark.parametrize("server,expect", [
    ("vpn.example.com", "vpn.example.com 443"),
    ("vpn.example.com:8443", "vpn.example.com 8443"),
    ("https://vpn.example.com", "vpn.example.com 443"),
    ("https://vpn.example.com/group", "vpn.example.com 443"),
    ("https://vpn.example.com:8443/group", "vpn.example.com 8443"),
    ("vpn.example.com/group", "vpn.example.com 443"),
    ("https://user@vpn.example.com:8443/g", "vpn.example.com 8443"),
    ("[2001:db8::1]", "2001:db8::1 443"),
    ("[2001:db8::1]:8443", "2001:db8::1 8443"),
    ("2001:db8::1", "2001:db8::1 443"),
])
def test_server_hostport(server, expect):
    body = 'server_hostport "%s"\nprintf "%%s %%s\\n" "$HOSTPORT_HOST" "$HOSTPORT_PORT"\n' % server
    r = _sh(SRC_COMMON, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == expect


def _nc_stub(tmp_path, script):
    """Write a fake `nc` and return its path (wait_for_server calls it via $NC_BIN)."""
    stub = tmp_path / "nc"
    stub.write_text(script)
    stub.chmod(0o755)
    return str(stub)


def test_wait_for_server_returns_at_once_when_reachable(tmp_path):
    nc = _nc_stub(tmp_path, "#!/bin/sh\nexit 0\n")
    r = _sh(SRC_COMMON, 'wait_for_server vpn.example.com && echo REACHABLE\n',
            extra_env={"NC_BIN": nc})
    assert r.returncode == 0, r.stderr
    assert "REACHABLE" in r.stdout
    assert "waiting for" not in r.stderr      # no wait announced on the happy path


def test_wait_for_server_times_out_when_unreachable(tmp_path):
    # Regression for the original bug: the probe MUST actually loop and then time out.
    # (The old route-based probe never looped at all -- macOS `route get` exits 0 even
    # with no default route, so the wait was dead code.) NET_WAIT_MAX is overridden so
    # the bounded loop finishes fast.
    nc = _nc_stub(tmp_path, "#!/bin/sh\nexit 1\n")
    r = _sh(SRC_COMMON, 'NET_WAIT_MAX=2\nwait_for_server vpn.example.com:8443 || echo TIMEDOUT\n',
            extra_env={"NC_BIN": nc})
    assert r.returncode == 0, r.stderr
    assert "TIMEDOUT" in r.stdout
    assert "waiting for vpn.example.com:8443" in r.stderr
    assert "still unreachable after 2s" in r.stderr


def test_wait_for_server_recovers_when_server_comes_back(tmp_path):
    # First probe fails, later ones succeed: exercises the retry path and the recovery log.
    tries = tmp_path / "tries"
    nc = _nc_stub(tmp_path, (
        '#!/bin/sh\n'
        'n=$(cat "%s" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "%s"\n'
        '[ "$n" -ge 2 ]\n' % (tries, tries)))
    r = _sh(SRC_COMMON, 'NET_WAIT_MAX=20\nwait_for_server vpn.example.com && echo OK\n',
            extra_env={"NC_BIN": nc})
    assert r.returncode == 0, r.stderr
    assert "OK" in r.stdout
    assert "is reachable; continuing" in r.stderr


def test_net_wait_max_is_at_least_throttle_interval():
    # The load-bearing invariant: launchd delays a respawn by (ThrottleInterval - runtime),
    # so the SUPERVISED wait must outlast the throttle window or an eventual give-up idles
    # out the rest. recovery_budget owns the supervised NET_WAIT_MAX.
    r = _sh(SRC_COMMON, 'recovery_budget 1\nprintf "%s %s\\n" "$NET_WAIT_MAX" "$THROTTLE_INTERVAL"\n')
    assert r.returncode == 0, r.stderr
    net_wait, throttle = (int(x) for x in r.stdout.split())
    assert net_wait >= throttle


# --- lib/common.sh: recovery_budget (supervisor-presence -> budget selection) ---
def test_recovery_budget_supervised():
    # OC_SUPERVISED=1 (launchd): give up fast (30) and wait out the whole throttle window.
    r = _sh(SRC_COMMON, 'recovery_budget 1\nprintf "%s %s\\n" "$RECONNECT_TIMEOUT" "$NET_WAIT_MAX"\n')
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["30", "300"]


def test_recovery_budget_unsupervised():
    # No supervisor: keep openconnect's long budget (300) and fail the wait fast (10).
    r = _sh(SRC_COMMON, 'recovery_budget ""\nprintf "%s %s\\n" "$RECONNECT_TIMEOUT" "$NET_WAIT_MAX"\n')
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["300", "10"]


def test_recovery_budget_config_value_wins():
    # An explicit reconnect_timeout (already in the env) must not be overridden.
    r = _sh(SRC_COMMON, 'RECONNECT_TIMEOUT=77\nrecovery_budget 1\nprintf "%s\\n" "$RECONNECT_TIMEOUT"\n')
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "77"


# --- lib/common.sh: wait_for_server SKIPS (does not stall) when it can't probe ---
def test_wait_for_server_skips_when_probe_tool_missing(tmp_path):
    # Regression: a missing/unusable nc must SKIP the gate (return 0 at once), not burn the
    # whole NET_WAIT_MAX on every connect -- the inverse of the original dead-code bug.
    r = _sh(SRC_COMMON, 'NET_WAIT_MAX=30\nwait_for_server vpn.example.com && echo PROCEED\n',
            extra_env={"NC_BIN": str(tmp_path / "no-such-nc")})
    assert r.returncode == 0, r.stderr
    assert "PROCEED" in r.stdout
    assert "waiting for" not in r.stderr


def test_wait_for_server_skips_on_malformed_server(tmp_path):
    # A server value that parses to no host / a non-numeric port must SKIP, not stall.
    nc = _nc_stub(tmp_path, "#!/bin/sh\nexit 1\n")   # would never succeed if it were run
    for bad in ("https://", "host:notaport"):
        r = _sh(SRC_COMMON, 'NET_WAIT_MAX=30\nwait_for_server "%s" && echo PROCEED\n' % bad,
                extra_env={"NC_BIN": nc})
        assert r.returncode == 0, r.stderr
        assert "PROCEED" in r.stdout, bad
        assert "waiting for" not in r.stderr, bad


def test_server_hostport_userinfo_uses_last_at(tmp_path):
    # A literal @ in userinfo (pasted password) must not corrupt the host: strip the LAST @.
    r = _sh(SRC_COMMON,
            'server_hostport "https://user:p@ss@vpn.example.com:8443/g"\n'
            'printf "%s %s\\n" "$HOSTPORT_HOST" "$HOSTPORT_PORT"\n')
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "vpn.example.com 8443"


# --- vpn-teardown: arg dispatch + sweep guard (kill path deliberately not exercised) ---
def _run_teardown(args, tmp_path, pgrep_out, pgrep_rc):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "pgrep"
    stub.write_text("#!/bin/sh\n" + (("echo %s\n" % pgrep_out) if pgrep_out else "") + "exit %d\n" % pgrep_rc)
    stub.chmod(0o755)
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    return subprocess.run(["sh", TEARDOWN, *args], capture_output=True, text=True, env=env,
                          timeout=30)


def test_teardown_usage_error():
    r = subprocess.run(["sh", TEARDOWN, "--bogus"], capture_output=True, text=True)
    assert r.returncode == 2
    assert "usage" in r.stderr


def test_teardown_sweep_is_noop_when_tunnel_up(tmp_path):
    # do_sweep must early-return (never yank a live tunnel's resolver files) if up.
    r = _run_teardown(["--sweep"], tmp_path, pgrep_out="4242", pgrep_rc=0)
    assert r.returncode == 0


def test_teardown_default_noop_when_not_connected(tmp_path):
    # No openconnect running -> nothing to kill, exit 0 before any signal is sent.
    r = _run_teardown([], tmp_path, pgrep_out="", pgrep_rc=1)
    assert r.returncode == 0
