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
CONNECT = os.path.join(REPO, "bin", "openconnect-auto-sso")
# Unlike the others, source the connect script by its LITERAL path, not "$OC_PROJ/...":
# its $PROJ ERE-guard tests override OC_PROJ to a metachar path, and we must still be able
# to locate the real script to source. OC_PROJ then only drives the guard/`$PROJ` value.
SRC_CONNECT = 'export OC_CONNECT_TEST=1; . "%s"' % CONNECT
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
    (tmp_path / "foreign.corp").write_text("nameserver 9.9.9.9\n")   # no marker, no port line
    # Same port (45353) but NO marker line: isolates the MARKER filter. foreign.corp above is
    # also protected by the port filter, so without this file removing the marker check would
    # go unnoticed; this file survives ONLY because sweep refuses files lacking our marker.
    (tmp_path / "portonly.corp").write_text("nameserver 127.0.0.1\nport 45353\n")
    body = '_port=45353\n_sweep_our_resolvers\n'
    r = _sh(SRC_VPNC, body, extra_env={"RESOLVER_DIR": str(tmp_path)})
    assert r.returncode == 0, r.stderr
    remaining = {p.name for p in tmp_path.iterdir()}
    assert remaining == {"c.corp", "foreign.corp", "portonly.corp"}


# --- vpnc-slice: proxy-state helpers (ownership invariant / orphan reclaim) ---
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


def test_is_dnsroute_rejects_arbitrary_dnsroute_py_command():
    # Finding 8: the matcher keys on the FULL "$PROJ/src/dnsroute.py" argv, not a bare
    # "dnsroute.py" substring -- else an unrelated process merely mentioning "dnsroute.py"
    # would be signalled as root. Spawn a decoy whose argv contains "dnsroute.py" but NOT
    # our real path, and confirm _is_dnsroute rejects it (the old substring match accepted it).
    decoy = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)  # /tmp/evil/dnsroute.py"])
    try:
        out = ""
        for _ in range(30):
            out = subprocess.run(["ps", "-p", str(decoy.pid), "-o", "command="],
                                 capture_output=True, text=True).stdout
            if "dnsroute.py" in out:
                break
            time.sleep(0.1)
        assert "dnsroute.py" in out          # the decoy DOES carry the bare substring...
        r = _sh(SRC_VPNC, '_is_dnsroute %d && echo YES || echo NO\n' % decoy.pid)
        assert r.stdout.strip() == "NO", (r.stderr, out)   # ...but is NOT our full path
    finally:
        decoy.terminate()
        decoy.wait(timeout=5)


# --- vpnc-slice: _may_touch_proxy ownership invariant (reclaim / teardown gate) -------
# Truth table: we may mutate this proxy's state iff it is ours, unowned, or owned by a
# PID that is no longer a live openconnect. The ONE case we must refuse is a live DIFFERENT
# openconnect on the same port (else one tunnel yanks another's proxy + /etc/resolver).
def test_may_touch_proxy_true_when_no_owner(tmp_path):
    pf = tmp_path / "proxy"
    pf.write_text("4242\n")          # line 1 only -- no owner recorded on line 2
    body = ('_pidfile="%s"\nVPNPID=999999\n'
            '_may_touch_proxy && echo TOUCH || echo LEAVE\n') % pf
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "TOUCH"


def test_may_touch_proxy_true_when_no_pidfile(tmp_path):
    body = ('_pidfile="%s"\nVPNPID=999999\n'
            '_may_touch_proxy && echo TOUCH || echo LEAVE\n') % (tmp_path / "nope")
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "TOUCH"


def test_may_touch_proxy_true_when_owner_is_us(tmp_path):
    # owner == our VPNPID -> ours (openconnect keeps its PID across an in-process reconnect,
    # so this reclaims our OWN old proxy). CRUCIAL: stub `ps` so the owner PID reads as a LIVE
    # openconnect, making the owner==VPNPID short-circuit the ONLY path to TOUCH -- if that
    # branch is broken, the fallthrough ps probe now sees a live openconnect and returns LEAVE.
    # (Without a live-openconnect stub the fallthrough would also yield TOUCH for the fake PID,
    # so the test would pass even with the self-ownership check disabled -- a tautology.)
    pf = tmp_path / "proxy"
    pf.write_text("4242\n7777\n")            # line 1 dnsroute 4242, line 2 owner == our VPNPID
    body = ('ps() { case "$*" in *7777*) echo "/opt/homebrew/bin/openconnect" ;; '
            '*) echo "/usr/bin/less" ;; esac; }\n'
            '_pidfile="%s"\nVPNPID=7777\n'
            '_may_touch_proxy && echo TOUCH || echo LEAVE\n') % pf
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "TOUCH"


def test_may_touch_proxy_false_for_live_different_openconnect(tmp_path):
    # A live DIFFERENT openconnect owner -> LEAVE. The `ps` stub is ARGUMENT-AWARE: it reports
    # openconnect ONLY for the owner PID on line 2 (55555), and a non-openconnect for the
    # dnsroute PID on line 1 (4242). So the LEAVE verdict depends on the invariant reading the
    # OWNER from line 2 -- if it read line 1 instead, ps would report a non-openconnect and it
    # would wrongly reclaim (TOUCH). This pins both the liveness probe AND the line-2 read.
    pf = tmp_path / "proxy"
    pf.write_text("4242\n55555\n")   # owner (line 2) 55555, different from VPNPID below
    body = ('ps() { case "$*" in *55555*) echo "/opt/homebrew/bin/openconnect" ;; '
            '*) echo "/usr/bin/less" ;; esac; }\n'
            '_pidfile="%s"\nVPNPID=999999\n'
            '_may_touch_proxy && echo TOUCH || echo LEAVE\n') % pf
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "LEAVE"


def test_may_touch_proxy_true_for_dead_owner(tmp_path):
    # A recorded owner that is no longer alive (or whose PID got reused by a non-openconnect)
    # is reclaimable. Use a reaped child's PID: definitively not a live openconnect.
    dead = subprocess.Popen(["true"]); dead.wait()
    pf = tmp_path / "proxy"
    pf.write_text("4242\n%d\n" % dead.pid)
    body = ('_pidfile="%s"\nVPNPID=999999\n'
            '_may_touch_proxy && echo TOUCH || echo LEAVE\n') % pf
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "TOUCH"


def test_may_touch_proxy_true_for_reused_non_openconnect_owner(tmp_path):
    # Owner PID reused by an unrelated live program (ps shows a non-openconnect comm) ->
    # reclaimable, since it is not the openconnect that recorded it.
    pf = tmp_path / "proxy"
    pf.write_text("4242\n55555\n")
    body = ('ps() { echo "/usr/bin/less"; }\n'
            '_pidfile="%s"\nVPNPID=999999\n'
            '_may_touch_proxy && echo TOUCH || echo LEAVE\n') % pf
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "TOUCH"


def test_may_touch_proxy_true_for_openconnect_lookalike_owner(tmp_path):
    # Finding 6: a reused owner PID belonging to an "openconnect-sso" / "openconnect-gui"
    # process -- whose comm CONTAINS the substring "openconnect" but is NOT openconnect (this
    # user runs openconnect-sso) -- must read as reclaimable. The old `grep -q openconnect`
    # substring match wrongly LEFT it; the basename-exact compare correctly TOUCHes it.
    pf = tmp_path / "proxy"
    pf.write_text("4242\n55555\n")
    body = ('ps() { echo "/opt/homebrew/bin/openconnect-sso"; }\n'
            '_pidfile="%s"\nVPNPID=999999\n'
            '_may_touch_proxy && echo TOUCH || echo LEAVE\n') % pf
    r = _sh(SRC_VPNC, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "TOUCH"


# --- vpnc-slice: failed-bind path is ownership-gated (findings 2 + 14) -----------------
def test_failed_bind_leaves_a_live_winners_state_intact(tmp_path):
    # Finding 14: when our dnsroute fails to bind because a live DIFFERENT tunnel holds the
    # port, WARN ONLY -- never rm the pidfile or sweep the winner's /etc/resolver files. Make
    # _may_touch_proxy see a LIVE different owner by stubbing `ps` so the recorded owner (55555)
    # reads as an openconnect; stub `nohup` so dnsroute never starts (failed-bind branch).
    resolv = tmp_path / "resolver"
    resolv.mkdir()
    _mk_resolver(resolv / "keep.corp", 45353)     # the winner's resolver file (our marker+port)
    pf = tmp_path / "proxy"
    pf.write_text("4242\n55555\n")                # the winner's pidfile (dnsroute 4242, owner 55555)
    body = (
        'nohup() { :; }\n'                        # dnsroute never starts -> failed-bind path
        'ps() { case "$*" in *55555*) echo /opt/homebrew/bin/openconnect;; esac; }\n'
        '_names="keep.corp"\n'
        'CISCO_SPLIT_DNS=""; CISCO_DEF_DOMAIN=""\n'
        'INTERNAL_IP4_DNS="10.0.0.53"; TUNDEV="utun-test"; VPNGATEWAY="10.0.0.1"\n'
        'VPNPID=999999\n'                         # we are a DIFFERENT tunnel
        '_port=45353\n_pidfile="%s"\n'
        '_proxy_connect\n'
        'echo DONE\n'
    ) % pf
    r = _sh(SRC_VPNC, body, extra_env={"RESOLVER_DIR": str(resolv)})
    assert r.returncode == 0, r.stderr
    assert "DONE" in r.stdout
    assert "failed to bind" in r.stderr
    assert pf.read_text() == "4242\n55555\n", "failed-bind wrongly rewrote the winner's pidfile"
    assert (resolv / "keep.corp").exists(), "failed-bind wrongly swept the winner's resolver file"


def test_failed_bind_sweeps_our_own_dead_port_files(tmp_path):
    # Finding 2: on OUR OWN failed rebind (recorded owner == our VPNPID, or a dead/absent
    # owner), the failed-bind path MUST clear our now-dead-port pidfile + resolver files so
    # routed domains degrade to default DNS instead of black-holing at a port nothing binds.
    resolv = tmp_path / "resolver"
    resolv.mkdir()
    _mk_resolver(resolv / "mine.corp", 45353)
    pf = tmp_path / "proxy"
    pf.write_text("4242\n999999\n")               # recorded owner == our VPNPID below
    body = (
        'nohup() { :; }\n'                        # dnsroute never starts -> failed-bind path
        'ps() { :; }\n'                           # no live owner anywhere
        '_names="mine.corp"\n'
        'CISCO_SPLIT_DNS=""; CISCO_DEF_DOMAIN=""\n'
        'INTERNAL_IP4_DNS="10.0.0.53"; TUNDEV="utun-test"; VPNGATEWAY="10.0.0.1"\n'
        'VPNPID=999999\n'                         # we own the record (in-process reconnect)
        '_port=45353\n_pidfile="%s"\n'
        '_proxy_connect\n'
        'echo DONE\n'
    ) % pf
    r = _sh(SRC_VPNC, body, extra_env={"RESOLVER_DIR": str(resolv)})
    assert r.returncode == 0, r.stderr
    assert "failed to bind" in r.stderr
    assert not pf.exists(), "failed-bind should remove our own dead-port pidfile"
    assert not (resolv / "mine.corp").exists(), "failed-bind should sweep our own dead-port file"


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


# --- install-autostart: dir_ok_for_repo + verify_repo_ancestors (repo-path guard) -----
# $connect is run by the login agent as YOU and reaches root via NOPASSWD openconnect, so any
# repo-path component another user can write, rename, or symlink-redirect is a passwordless-
# root vector. Unlike dir_is_safe (which vets the root teardown helper and demands root
# ownership) the owner here may be root OR you -- but a component owned by a DIFFERENT non-root
# user, a symlink, or a group/other-writable dir is refused, at EVERY level of the path.
@pytest.mark.parametrize("mode,expect", [
    (0o700, "OK"), (0o755, "OK"), (0o750, "OK"), (0o705, "OK"),   # no group/other write
    (0o770, "NO"), (0o720, "NO"), (0o775, "NO"),                  # group-writable
    (0o702, "NO"), (0o706, "NO"), (0o707, "NO"),                  # other-writable
    (0o777, "NO"),                                                # both
])
def test_dir_ok_for_repo_mode_bits(tmp_path, mode, expect):
    # Self-owned dir: the owner check passes (it's YOURS), so only the group/other-write bits
    # decide -- exercising the shared _dir_component_safe mode-bit case via the repo predicate.
    d = tmp_path / ("m%o" % mode)
    d.mkdir()
    d.chmod(mode)
    r = _sh(SRC_INSTALL, 'dir_ok_for_repo "%s" && echo OK || echo NO' % d)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == expect, oct(mode)


def test_dir_ok_for_repo_fails_closed_on_missing(tmp_path):
    # A path that can't be stat'd must fail closed (treated as unsafe), not accepted.
    r = _sh(SRC_INSTALL, 'dir_ok_for_repo "%s" && echo OK || echo NO' % (tmp_path / "nope"))
    assert r.stdout.strip() == "NO"


def test_dir_ok_for_repo_rejects_symlink(tmp_path):
    # stat -f is lstat, so a symlinked component (mode l...) is rejected even though it's
    # self-owned -- otherwise exec/install would follow it to an unchecked target. The link is
    # owned by YOU (so the owner check passes), so ONLY the l*) branch can reject it here.
    target = tmp_path / "target"
    target.mkdir()
    target.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(target)
    r = _sh(SRC_INSTALL, 'dir_ok_for_repo "%s" && echo OK || echo NO' % link)
    assert r.stdout.strip() == "NO"


def test_dir_ok_for_repo_rejects_foreign_owner(tmp_path):
    # A self-owned dir must be rejected when the invoking uid is neither 0 nor the owner --
    # i.e. an ancestor owned by a DIFFERENT non-root user. Creating a truly foreign-owned dir
    # needs root (chown), so we spoof $uid to a bogus value instead: the dir (owned by YOU) is
    # then neither root- nor self-owned from the predicate's view, exercising the owner branch.
    d = tmp_path / "d"
    d.mkdir()
    d.chmod(0o700)
    r = _sh(SRC_INSTALL, 'uid=424242\ndir_ok_for_repo "%s" && echo OK || echo NO' % d)
    assert r.stdout.strip() == "NO"


def test_verify_repo_ancestors_accepts_clean_user_chain(tmp_path):
    # Every existing component of a private, self-owned chain (root-owned system dirs up top,
    # your own dirs below) passes. realpath first so a symlinked $TMPDIR prefix (on macOS
    # /var -> /private/var) isn't itself the offender -- we're vetting the user-owned tail.
    base = os.path.realpath(str(tmp_path))
    os.makedirs(base + "/a/b")
    os.chmod(base + "/a", 0o755)
    os.chmod(base + "/a/b", 0o755)
    r = _sh(SRC_INSTALL, 'verify_repo_ancestors "%s/a/b/leaf" && echo OK || echo BAD' % base)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "OK"


def test_verify_repo_ancestors_refuses_symlinked_component(tmp_path):
    # A symlink ANYWHERE in the chain is refused: the walk lstat's each component and rejects
    # mode l... (a self-owned link passes the owner check, so the symlink branch is what bites).
    base = os.path.realpath(str(tmp_path))
    os.makedirs(base + "/real/b")
    os.symlink(base + "/real", base + "/link")
    r = _sh(SRC_INSTALL, 'verify_repo_ancestors "%s/link/b/leaf" && echo OK || echo BAD' % base)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "BAD"
    assert "refusing to install" in r.stderr


def test_verify_repo_ancestors_refuses_group_writable_ancestor(tmp_path):
    # A group/other-writable ANCESTOR (not just the leaf) is enough: unlink/rename is governed
    # by the parent's write bit, so a loose mid-path dir lets another user swap the leaf.
    base = os.path.realpath(str(tmp_path))
    os.makedirs(base + "/loose/sub")
    os.chmod(base + "/loose", 0o775)                 # group-writable ancestor
    r = _sh(SRC_INSTALL, 'verify_repo_ancestors "%s/loose/sub/leaf" && echo OK || echo BAD' % base)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "BAD"
    assert "refusing to install" in r.stderr


def test_verify_repo_ancestors_refuses_foreign_owned_ancestor(tmp_path):
    # An ancestor owned by a DIFFERENT non-root user is refused (they can rename components).
    # Making a truly foreign-owned dir needs root (chown); lacking that, we spoof the invoking
    # uid so our own self-owned ancestors read as foreign -- exercising the same owner branch of
    # the walk. (If a future env CAN chown to another uid, a real foreign dir works identically.)
    base = os.path.realpath(str(tmp_path))
    os.makedirs(base + "/a/b")
    os.chmod(base + "/a", 0o755)
    os.chmod(base + "/a/b", 0o755)
    r = _sh(SRC_INSTALL,
            'uid=424242\nverify_repo_ancestors "%s/a/b/leaf" && echo OK || echo BAD' % base)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "BAD"
    assert "refusing to install" in r.stderr


def test_do_install_refuses_group_or_other_writable_proj(tmp_path):
    # Integration: do_install must ABORT (before any sudo) when $proj is group/other-writable.
    # We override $proj/$connect after sourcing and point them at a world-writable fake repo
    # with an executable connect stub (so the earlier `-x` check passes). The refusal is
    # ordered before every privileged/mutating step, so this never touches sudo.
    proj = tmp_path / "shared-clone"
    (proj / "bin").mkdir(parents=True)
    connect = proj / "bin" / "openconnect-auto-sso"
    connect.write_text("#!/bin/sh\n:\n")
    connect.chmod(0o755)
    proj.chmod(0o777)                                    # world-writable repo root
    rp = os.path.realpath(str(proj))
    body = ('proj="%s"\nconnect="%s/bin/openconnect-auto-sso"\ndo_install\n') % (rp, rp)
    r = _sh(SRC_INSTALL, body)
    assert r.returncode != 0
    assert "group/other-writable" in r.stderr
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
    rp = os.path.realpath(str(proj))
    body = ('proj="%s"\nconnect="%s/bin/openconnect-auto-sso"\ndo_install\n') % (rp, rp)
    r = _sh(SRC_INSTALL, body)
    assert r.returncode != 0
    assert "group/other-writable" in r.stderr
    assert "refusing to install" in r.stderr


def test_do_install_refuses_group_or_other_writable_interior_dir(tmp_path):
    # Finding 1: the ROOT vpnc-slice wrapper sources $proj/lib/common.sh and execs
    # $proj/src/dnsroute.py + $proj/.venv/bin/python as root, so those INTERIOR dirs must be
    # unsubvertable too -- not just $proj and $proj/bin. A private repo root but a world-writable
    # lib/ (whose common.sh root sources) is a plant-code-as-root vector; do_install must refuse.
    proj = tmp_path / "repo"
    (proj / "bin").mkdir(parents=True)
    (proj / "lib").mkdir()
    (proj / "lib" / "common.sh").write_text(":\n")
    connect = proj / "bin" / "openconnect-auto-sso"
    connect.write_text("#!/bin/sh\n:\n")
    connect.chmod(0o755)
    proj.chmod(0o755); (proj / "bin").chmod(0o755)       # root + bin/ private...
    (proj / "lib").chmod(0o777)                          # ...but lib/ world-writable
    rp = os.path.realpath(str(proj))
    body = ('proj="%s"\nconnect="%s/bin/openconnect-auto-sso"\ndo_install\n') % (rp, rp)
    r = _sh(SRC_INSTALL, body)
    assert r.returncode != 0
    # "runs code from it" is UNIQUE to the interior-component message (the ancestor-walk
    # refusal shares "group/other-writable"), pinning the failure to the interior /lib check.
    assert "runs code from it" in r.stderr
    assert rp + "/lib" in r.stderr


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
    # so the keepalive wait must outlast the throttle window or an eventual give-up idles
    # out the rest. recovery_budget owns the keepalive NET_WAIT_MAX.
    r = _sh(SRC_COMMON, 'recovery_budget keepalive\nprintf "%s %s\\n" "$NET_WAIT_MAX" "$THROTTLE_INTERVAL"\n')
    assert r.returncode == 0, r.stderr
    net_wait, throttle = (int(x) for x in r.stdout.split())
    assert net_wait >= throttle


# --- lib/common.sh: recovery_budget (OC_LAUNCHD mode -> budget selection) ---
def test_recovery_budget_keepalive():
    # keepalive (launchd's KeepAlive respawns us): give up fast (30) and wait out the whole
    # throttle window (300), so an eventual exit respawns immediately.
    r = _sh(SRC_COMMON, 'recovery_budget keepalive\nprintf "%s %s\\n" "$RECONNECT_TIMEOUT" "$NET_WAIT_MAX"\n')
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["30", "300"]


def test_recovery_budget_once():
    # --once runs at login but has NO respawner, so it KEEPS the long reconnect budget (300)
    # yet still waits out a slow boot network (300): the two concerns are decided separately.
    r = _sh(SRC_COMMON, 'recovery_budget once\nprintf "%s %s\\n" "$RECONNECT_TIMEOUT" "$NET_WAIT_MAX"\n')
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["300", "300"]


def test_recovery_budget_unsupervised():
    # No launchd mode (interactive): keep openconnect's long budget (300) and fail the wait
    # fast (10) -- a human is watching.
    r = _sh(SRC_COMMON, 'recovery_budget ""\nprintf "%s %s\\n" "$RECONNECT_TIMEOUT" "$NET_WAIT_MAX"\n')
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["300", "10"]


def test_recovery_budget_config_value_wins():
    # An explicit reconnect_timeout (already in the env) must not be overridden.
    r = _sh(SRC_COMMON, 'RECONNECT_TIMEOUT=77\nrecovery_budget keepalive\nprintf "%s\\n" "$RECONNECT_TIMEOUT"\n')
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


# --- bin/openconnect-auto-sso: OC_CONNECT_TEST=1 seam ---------------------------------
# The connect script runs its whole two-phase flow at top level (config load, startup sweeps,
# auth, sudo). OC_CONNECT_TEST=1 guards that flow off so sourcing defines ONLY the pure helpers
# (_shq / apply_launch_budget / _build_vs) and runs the $PROJ ERE-guard -- no side effects. That
# lets these tests exercise the previously-uncovered connect-script logic offline.
def test_connect_sources_clean_under_seam():
    # The seam contract: sourcing under OC_CONNECT_TEST=1 emits nothing and exits 0 (no config
    # load, no auth, no sudo). Also confirms a metachar-free $PROJ passes the ERE guard.
    r = _sh(SRC_CONNECT, ':\n')
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""
    assert r.stderr == ""


def test_connect_shq_wraps_and_escapes_apostrophe():
    # _shq single-quotes its arg and splices an embedded ' as '\'' so a space/apostrophe in a
    # path survives openconnect re-parsing the Phase-2 -s string via sh.
    r = _sh(SRC_CONNECT, 'printf "%s" "$(_shq "$P")"\n', extra_env={"P": "a b'c"})
    assert r.returncode == 0, r.stderr
    assert r.stdout == "'a b'\\''c'"


@pytest.mark.parametrize("path", [
    "/opt/my repo", "/it's/a path", "/a$b/c", "/x;rm -rf/y", "/plain/path", "/tab\tsep",
])
def test_connect_shq_roundtrips_through_eval(path):
    # The real contract: eval'ing the quoted word recovers the ORIGINAL string byte-for-byte,
    # even with spaces, apostrophes, $, ;, tabs. A broken escape would corrupt the round-trip.
    body = ('q=$(_shq "$P")\n'
            'eval "back=$q"\n'
            '[ "$back" = "$P" ] && echo ROUNDTRIP_OK || echo MISMATCH:"$back"\n')
    r = _sh(SRC_CONNECT, body, extra_env={"P": path})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "ROUNDTRIP_OK", (path, r.stdout)


@pytest.mark.parametrize("mode,expect", [
    ("keepalive", ["30", "300"]),   # respawned by launchd: give up fast, wait out the throttle
    ("once", ["300", "300"]),       # at-login but NO respawner: long budget, long boot-net wait
    ("", ["300", "10"]),            # interactive: long budget, short wait (a human is watching)
])
def test_connect_apply_launch_budget_wires_oc_launchd(mode, expect):
    # The connect script feeds $OC_LAUNCHD (NOT the removed OC_SUPERVISED, not a hardcoded mode)
    # to recovery_budget. Reverting the wiring would make keepalive/once stop selecting 30/300.
    body = 'apply_launch_budget\nprintf "%s %s\\n" "$RECONNECT_TIMEOUT" "$NET_WAIT_MAX"\n'
    r = _sh(SRC_CONNECT, body, extra_env={"OC_LAUNCHD": mode})
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == expect


def test_connect_apply_launch_budget_config_reconnect_wins():
    # A config-provided reconnect_timeout (already in the env as RECONNECT_TIMEOUT) is preserved
    # through the connect script's wiring, not clobbered by the launch-mode default.
    body = 'RECONNECT_TIMEOUT=77\napply_launch_budget\nprintf "%s\\n" "$RECONNECT_TIMEOUT"\n'
    r = _sh(SRC_CONNECT, body, extra_env={"OC_LAUNCHD": "keepalive"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "77"


@pytest.mark.parametrize("name", [
    "a+b", "a|b", "a(b)", "a*b", "a[b]", "a{b}", "a^b", "a.b",
])
def test_connect_metachar_proj_path_sources_fine(tmp_path, name):
    # Finding 7: the old B10 $PROJ-metacharacter guard is GONE -- the backstop / _end_browser now
    # match by a fixed literal + grep -F, never splicing $PROJ into an ERE -- so a repo path with
    # regex metacharacters (common on macOS: "Projects (work)", "C++") sources and runs fine.
    # Point $PROJ at such a dir whose lib/ symlinks to the real repo and confirm the seam sources
    # cleanly (body reached) instead of refusing.
    proj = tmp_path / name
    proj.mkdir()
    (proj / "lib").symlink_to(os.path.join(REPO, "lib"))
    r = _sh(SRC_CONNECT, 'echo REACHED_BODY\n', extra_env={"OC_PROJ": str(proj)})
    assert r.returncode == 0, r.stderr
    assert "REACHED_BODY" in r.stdout


def test_connect_refuses_when_executed_with_seam_var():
    # Finding 10: OC_CONNECT_TEST=1 is a SOURCING seam for tests. If it leaks into a real
    # EXECUTED run, the whole connect flow would be guarded off and the script would exit 0
    # having done nothing (a silent no-op -- the worst failure for a VPN tool). Executing the
    # script with the var set must refuse LOUDLY (non-zero + a clear message). ($0 basename is
    # the script name when executed, but "sh" when the harness sources it -- so the seam tests
    # above are unaffected.)
    r = subprocess.run([CONNECT], capture_output=True, text=True,
                       env=dict(os.environ, OC_CONNECT_TEST="1"), timeout=30)
    assert r.returncode != 0
    assert "EXECUTED" in r.stderr


def test_connect_build_vs_full_includes_flags_and_quotes():
    # Phase-2 -s assembly: abs paths single-quoted (survive a space when openconnect re-splits
    # the string via sh), --proxy carries the validated names+port+quoted pidfile, and the
    # -i/-I/-S/--write-dns toggles all appear when their config vars are on.
    body = (
        'PROJ="/opt/my repo"\nVPN_SLICE="/usr/local/bin/vpn-slice"\n'
        'PROXY_NAMES="a.corp,b.corp"; PROXY_PORT=45353; PROXY_PIDFILE="/var/run/p.45353"\n'
        'KEEPALIVE_HOST="@dns"; KA_DNS_FILE="/tmp/x.dns"; OC_DUMP=""\n'
        'ALLOW_INCOMING=1; ROUTE_INTERNAL=1; ROUTE_SPLITS=1; SPLIT_ROUTES="10.0.0.0/8"\n'
        '_build_vs\nprintf "%s" "$vs"\n'
    )
    r = _sh(SRC_CONNECT, body)
    assert r.returncode == 0, r.stderr
    vs = r.stdout
    assert "'/opt/my repo/bin/vpnc-slice'" in vs      # wrapper path quoted (has a space)
    assert "'/usr/local/bin/vpn-slice'" in vs         # vpn-slice bin quoted
    assert "--proxy a.corp,b.corp 45353 '/var/run/p.45353'" in vs
    assert "--write-dns '/tmp/x.dns'" in vs
    assert " -i" in vs and " -I" in vs and " -S" in vs
    assert vs.endswith("10.0.0.0/8")                  # explicit split route appended last


def test_connect_build_vs_minimal_omits_optional_flags():
    # With no proxy/keepalive/route flags set, $vs is exactly the quoted wrapper + quoted
    # vpn-slice bin -- none of --proxy/--write-dns/-i/-I/-S may leak in.
    body = (
        'PROJ="/opt/repo"\nVPN_SLICE="/usr/local/bin/vpn-slice"\n'
        'PROXY_NAMES=""; PROXY_PORT=45353; PROXY_PIDFILE="/var/run/p"\n'
        'KEEPALIVE_HOST=""; KA_DNS_FILE="/tmp/x"; OC_DUMP=""\n'
        'ALLOW_INCOMING=0; ROUTE_INTERNAL=0; ROUTE_SPLITS=0; SPLIT_ROUTES=""\n'
        '_build_vs\nprintf "[%s]" "$vs"\n'
    )
    r = _sh(SRC_CONNECT, body)
    assert r.returncode == 0, r.stderr
    assert r.stdout == "['/opt/repo/bin/vpnc-slice' '/usr/local/bin/vpn-slice']"


def test_connect_refuse_block_removed():
    # Step A deleted the "refuse a second instance" block (the _running_oc line-2 probe that
    # aborted a second run with "already connected"). Assert those removed tokens are gone, so a
    # regression re-introducing the lockout is caught. The unrelated resolver-sweep warning "an
    # openconnect is already running" is a DIFFERENT message and is intentionally not matched.
    with open(CONNECT) as f:
        src = f.read()
    assert "_running_oc" not in src
    assert "already connected" not in src
