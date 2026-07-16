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


def _sh(setup_source, body, extra_env=None, strict=False):
    """Source `setup_source`, then run `body`; return CompletedProcess.

    By default the body runs with `set +eu` (relaxed) so tests can use unguarded constructs.
    Pass strict=True to run the body under the sourced script's OWN `set -eu` -- REQUIRED to
    catch errexit regressions (a function that leaks a non-zero status and aborts a
    `_x=$(...)` caller). The relaxed default MASKS that class -- it is exactly what hid the
    `_pids_matching` set -e abort (finding 1) through two review rounds.
    """
    env = dict(os.environ, OC_PROJ=REPO)
    if extra_env:
        env.update(extra_env)
    relax = "" if strict else "set +eu\n"
    script = "%s\n%s%s\n" % (setup_source, relax, body)
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


# --- vpnc-slice: self-gated proxy primitives (E1 / finding 12) -------------------------
def test_sweep_our_resolvers_self_gates_on_live_winner(tmp_path):
    # E1/finding 12: _sweep_our_resolvers now self-gates (a leading `_may_touch_proxy || return
    # 0`), so removing resolver files can NEVER touch a live DIFFERENT tunnel's, by construction
    # -- even when called directly with no external gate. A live winner (55555) owns the port.
    resolv = tmp_path / "resolver"; resolv.mkdir()
    _mk_resolver(resolv / "keep.corp", 45353)
    pf = tmp_path / "proxy"; pf.write_text("4242\n55555\n")   # owner 55555 = a live openconnect
    body = (
        'ps() { case "$*" in *55555*) echo /opt/homebrew/bin/openconnect ;; esac; }\n'
        'VPNPID=999999\n_port=45353\n_pidfile="%s"\n'
        '_sweep_our_resolvers\necho DONE\n'
    ) % str(pf)
    r = _sh(SRC_VPNC, body, extra_env={"RESOLVER_DIR": str(resolv)})
    assert r.returncode == 0, r.stderr
    assert "DONE" in r.stdout
    assert (resolv / "keep.corp").exists(), "self-gate must protect a live winner's resolver file"


def test_sweep_our_resolvers_still_sweeps_when_unowned(tmp_path):
    # The self-gate must NOT over-refuse: with no recorded owner (no pidfile set), the sweep
    # still runs (this is the teardown/no-proxy path the existing sweep tests rely on).
    resolv = tmp_path / "resolver"; resolv.mkdir()
    _mk_resolver(resolv / "mine.corp", 45353)
    r = _sh(SRC_VPNC, '_port=45353\n_sweep_our_resolvers\necho DONE\n',
            extra_env={"RESOLVER_DIR": str(resolv)})
    assert r.returncode == 0, r.stderr
    assert not (resolv / "mine.corp").exists(), "unowned sweep must still remove our-port files"


def test_clear_proxy_state_clears_own_and_sweeps(tmp_path):
    # _clear_proxy_state (self-gated teardown): when we own the record, kill our recorded
    # dnsroute (argv-confirmed), remove the pidfile + .ready, and sweep our resolver files.
    resolv = tmp_path / "resolver"; resolv.mkdir()
    _mk_resolver(resolv / "mine.corp", 45353)
    pf = tmp_path / "proxy"; pf.write_text("4242\n999999\n")   # owner == our VPNPID
    kl = tmp_path / "killlog"
    body = (
        'kill() { echo "$@" >> "%s"; }\n'
        'ps() { case "$*" in *4242*) echo "/x/.venv/bin/python /x/src/dnsroute.py --port 45353" ;; esac; }\n'
        'PROJ="/x"\nVPNPID=999999\n_port=45353\n_pidfile="%s"\n'
        ': > "%s.ready"\n'
        '_clear_proxy_state\necho DONE\n'
    ) % (str(kl), str(pf), str(pf))
    r = _sh(SRC_VPNC, body, extra_env={"RESOLVER_DIR": str(resolv)})
    assert r.returncode == 0, r.stderr
    assert "DONE" in r.stdout
    killed = kl.read_text() if kl.exists() else ""
    assert "4242" in killed, "should kill our recorded dnsroute"
    assert not pf.exists(), "pidfile removed"
    assert not (tmp_path / "proxy.ready").exists(), ".ready removed"
    assert not (resolv / "mine.corp").exists(), "our resolver file swept"


def test_clear_proxy_state_leaves_live_different_owner(tmp_path):
    # _clear_proxy_state must NO-OP when a live DIFFERENT openconnect owns the port (finding 14):
    # its dnsroute, pidfile, and resolver files are all left intact.
    resolv = tmp_path / "resolver"; resolv.mkdir()
    _mk_resolver(resolv / "keep.corp", 45353)
    pf = tmp_path / "proxy"; pf.write_text("4242\n55555\n")   # owner 55555 = a live openconnect
    kl = tmp_path / "killlog"
    body = (
        'kill() { echo "$@" >> "%s"; }\n'
        'ps() { case "$*" in *55555*) echo /opt/homebrew/bin/openconnect ;; '
        '*4242*) echo "/x/src/dnsroute.py" ;; esac; }\n'
        'PROJ="/x"\nVPNPID=999999\n_port=45353\n_pidfile="%s"\n'
        '_clear_proxy_state\necho DONE\n'
    ) % (str(kl), str(pf))
    r = _sh(SRC_VPNC, body, extra_env={"RESOLVER_DIR": str(resolv)})
    assert r.returncode == 0, r.stderr
    killed = kl.read_text() if kl.exists() else ""
    assert "4242" not in killed, "must not kill the winner's dnsroute"
    assert pf.exists(), "winner's pidfile left intact"
    assert (resolv / "keep.corp").exists(), "winner's resolver file left intact"


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


def test_do_install_refuses_group_or_other_writable_libexec(tmp_path):
    # Finding 2: $proj/libexec/vpn-teardown is `sudo install`ed root-owned and NOPASSWD-granted,
    # so a group/other-writable libexec (where an attacker could swap the teardown SOURCE before
    # install copies it to root) must be refused -- it was missing from the interior vet list.
    proj = tmp_path / "repo"
    (proj / "bin").mkdir(parents=True)
    (proj / "libexec").mkdir()
    (proj / "libexec" / "vpn-teardown").write_text("#!/bin/sh\n:\n")
    connect = proj / "bin" / "openconnect-auto-sso"
    connect.write_text("#!/bin/sh\n:\n"); connect.chmod(0o755)
    proj.chmod(0o755); (proj / "bin").chmod(0o755)
    (proj / "libexec").chmod(0o777)                      # libexec world-writable
    rp = os.path.realpath(str(proj))
    body = ('proj="%s"\nconnect="%s/bin/openconnect-auto-sso"\ndo_install\n') % (rp, rp)
    r = _sh(SRC_INSTALL, body)
    assert r.returncode != 0
    assert "runs code from it" in r.stderr
    assert rp + "/libexec" in r.stderr


# --- install-autostart: verify_repo_interior (Phase B recursive vet) -------------------
# The enumerated top-level list is replaced by a recursive find over the code roots; these
# pin the properties that matters -- deep files ARE walked, the legit .venv/bin interpreter
# symlink IS exempt, and symlink/foreign-owner refusals still fire anywhere under the tree.
def test_verify_repo_interior_refuses_deep_writable_venv_file(tmp_path):
    # Phase B core: a group/other-writable file DEEP under .venv/lib/.../site-packages (a .pth
    # root's python executes) is refused -- the recursive walk catches what the old enumerated
    # top-level list (which checked only .venv/.venv/bin/.venv/lib themselves) missed.
    proj = os.path.realpath(str(tmp_path / "repo"))
    deep = proj + "/.venv/lib/python3.13/site-packages"
    os.makedirs(deep)
    pth = deep + "/evil.pth"
    with open(pth, "w") as f:
        f.write("import os\n")
    os.chmod(pth, 0o666)                              # world-writable .pth
    r = _sh(SRC_INSTALL, 'verify_repo_interior "%s" && echo OK || echo BAD' % proj)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "BAD"
    assert pth in r.stderr


def test_verify_repo_interior_accepts_clean_tree_with_venv_python_symlink(tmp_path):
    # A clean interior with the LEGIT .venv/bin/python interpreter symlink must be ACCEPTED --
    # the symlink is exempted (it points at the system/Homebrew python). Everything else is a
    # non-symlink, not group/other-writable, and self-owned. (This is the case the full sudo
    # install path can't reach, which is why verify_repo_interior is split out.)
    proj = os.path.realpath(str(tmp_path / "repo"))
    os.makedirs(proj + "/bin")
    os.makedirs(proj + "/.venv/bin")
    with open(proj + "/bin/openconnect-auto-sso", "w") as f:
        f.write("#!/bin/sh\n:\n")
    os.chmod(proj + "/bin/openconnect-auto-sso", 0o755)
    os.symlink("/usr/bin/python3", proj + "/.venv/bin/python")   # the interpreter link uv makes
    r = _sh(SRC_INSTALL, 'verify_repo_interior "%s" && echo OK || echo BAD' % proj)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "OK"


def test_verify_repo_interior_refuses_symlink_outside_venv_bin(tmp_path):
    # A symlink ANYWHERE except under .venv/bin is refused (only the interpreter links are
    # exempt) -- e.g. a src/ file swapped for a symlink to attacker code. The old enumerated
    # list only named src/*.py, so a NEW/renamed src symlink could slip past; the walk catches it.
    proj = os.path.realpath(str(tmp_path / "repo"))
    os.makedirs(proj + "/src")
    os.symlink("/etc/hosts", proj + "/src/evil.py")
    r = _sh(SRC_INSTALL, 'verify_repo_interior "%s" && echo OK || echo BAD' % proj)
    assert r.stdout.strip() == "BAD"
    assert proj + "/src/evil.py" in r.stderr


def test_verify_repo_interior_refuses_foreign_owned(tmp_path):
    # A file owned by neither root nor you is refused. A truly foreign-owned file needs root to
    # create, so spoof $uid to a bogus value: our own self-owned files then read as foreign,
    # exercising the `! -user 0 ! -user $uid` arm (same trick as the ancestor foreign-owner test).
    proj = os.path.realpath(str(tmp_path / "repo"))
    os.makedirs(proj + "/bin")
    with open(proj + "/bin/openconnect-auto-sso", "w") as f:
        f.write("#!/bin/sh\n:\n")
    os.chmod(proj + "/bin/openconnect-auto-sso", 0o755)
    r = _sh(SRC_INSTALL, 'uid=424242\nverify_repo_interior "%s" && echo OK || echo BAD' % proj)
    assert r.stdout.strip() == "BAD"


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


def test_connect_refuses_when_executed_via_renamed_symlink(tmp_path):
    # Finding 7: the executed-refuse now keys on the RESOLVED basename (symlinks followed), so a
    # differently-NAMED symlink to the connect script can no longer bypass it. The old ${0##*/}
    # guard saw "vpnvpn" (!= openconnect-auto-sso) and silently no-op'd; the resolved guard
    # follows the link to openconnect-auto-sso and refuses. (Executing the symlink runs the real
    # script with $0 = the symlink path, which the resolution loop chases to the real file.)
    link = tmp_path / "vpnvpn"
    link.symlink_to(CONNECT)
    r = subprocess.run([str(link)], capture_output=True, text=True,
                       env=dict(os.environ, OC_CONNECT_TEST="1"), timeout=30)
    assert r.returncode != 0
    assert "EXECUTED" in r.stderr


def test_install_refuses_when_executed_with_seam_var():
    # Finding 7/10: OC_INSTALL_TEST=1 is a SOURCING seam. If it leaks into a real EXECUTED run
    # the dispatch is skipped -> the installer silently does nothing (and a poisoned OC_PROJ
    # could redirect $proj). Executing it with the var set must refuse LOUDLY, before sourcing
    # common.sh or touching sudo. Pass the read-only `status` subcommand so a regression that
    # reached dispatch still couldn't mutate anything.
    r = subprocess.run([os.path.join(REPO, "install-autostart.sh"), "status"],
                       capture_output=True, text=True,
                       env=dict(os.environ, OC_INSTALL_TEST="1"), timeout=30)
    assert r.returncode != 0
    assert "EXECUTED" in r.stderr


def test_vpnc_slice_refuses_when_executed_with_seam_var():
    # Finding 7/10: OC_VPNC_SLICE_TEST=1 is a SOURCING seam. If it leaks into a real EXECUTED
    # run (the root vpnc-script under openconnect) the directive loop + exec are skipped ->
    # routes/DNS silently never set up. Executing it with the var set must refuse LOUDLY, before
    # sourcing common.sh or running any directive.
    r = subprocess.run([os.path.join(REPO, "bin", "vpnc-slice")],
                       capture_output=True, text=True,
                       env=dict(os.environ, OC_VPNC_SLICE_TEST="1"), timeout=30)
    assert r.returncode != 0
    assert "EXECUTED" in r.stderr


def test_end_browser_reaps_only_the_recorded_pid(tmp_path):
    # Findings 3/8: _end_browser reaps EXACTLY the PID this run's helper recorded in
    # $VPN_BROWSER_PIDFILE -- NEVER a concurrent same-repo run's helper (a DIFFERENT live PID
    # whose argv also matches), and NEVER via a process scan. Stub kill/ps so we observe targets
    # without real signals; `kill -0 <p>` reports alive until <p> is TERM'd (a per-PID dead
    # marker) so the wait ends. pgrep is stubbed to a LOUD marker: the new PID-only reaper must
    # never invoke it (the old argv-pattern fallback did).
    H = "/x/src/vpn_browser.py"
    pf = tmp_path / "helper.pid"; pf.write_text("11111\n")   # OUR recorded helper PID
    kl = tmp_path / "killlog"; dm = str(tmp_path / "dead.")
    body = (
        'kill() { _s=$1; shift; case "$_s" in\n'
        '  -0) [ -f "%s$1" ] && return 1; return 0 ;;\n'
        '  *) for _p in "$@"; do echo "$_s $_p" >> "%s"; : > "%s$_p"; done ;;\n'
        'esac; }\n'
        'ps() { case "$*" in *11111*) echo "/py %s u" ;; esac; }\n'
        'pgrep() { echo PGREP_CALLED >&2; }\n'   # must NOT be reached (no pattern fallback)
        'sleep() { :; }\n'
        '_HELPER_FULL="%s"\nVPN_BROWSER_PIDFILE="%s"\n'
        '_end_browser\necho DONE\n'
    ) % (dm, kl, dm, H, H, str(pf))
    r = _sh(SRC_CONNECT, body, strict=True)
    assert r.returncode == 0, r.stderr
    assert "DONE" in r.stdout
    assert "PGREP_CALLED" not in r.stderr, "must never process-scan (findings 3/8)"
    killed = kl.read_text() if kl.exists() else ""
    assert "11111" in killed, "must reap the recorded helper PID"
    assert not pf.exists(), "pidfile removed after reaping"


def test_end_browser_dead_recorded_pid_removes_pidfile_and_is_idempotent(tmp_path):
    # Strict set -eu: a recorded PID that is NOT alive -> our helper already exited; _end_browser
    # cleans up (removes the pidfile) and returns 0, never pattern-reaps. The trap-chained 2nd
    # call reads no pidfile -> a clean no-op.
    pf = tmp_path / "helper.pid"; pf.write_text("11111\n")
    kl = tmp_path / "killlog"
    body = (
        'kill() { case "$1" in -0) return 1 ;; *) echo "$@" >> "%s" ;; esac; }\n'   # -0: always DEAD
        'ps() { echo "/x/src/vpn_browser.py" ; }\n'
        '_HELPER_FULL="/x/src/vpn_browser.py"\nVPN_BROWSER_PIDFILE="%s"\n'
        '_end_browser\n'          # 1st: dead recorded PID -> cleanup, no signal
        '_end_browser\n'          # 2nd: pidfile gone -> no-op
        'echo DONE\n'
    ) % (str(kl), str(pf))
    r = _sh(SRC_CONNECT, body, strict=True)
    assert r.returncode == 0, r.stderr
    assert "DONE" in r.stdout
    assert (kl.read_text() if kl.exists() else "") == "", "a dead recorded PID must never be signaled"
    assert not pf.exists(), "pidfile removed"


def test_end_browser_no_pattern_reap_without_recorded_pid(tmp_path):
    # Findings 3/6: the old argv-pattern fallback is GONE. If the helper crashed BEFORE writing
    # its pidfile (no recorded PID), _end_browser must do NOTHING -- never a process scan that
    # could kill a CONCURRENT same-repo run's live helper. A leaked crashed-early helper is the
    # far lesser evil than cross-run collateral; the parent-death watch in vpn_browser.py + the
    # backstop already bound a genuinely stuck helper.
    H = "/x/src/vpn_browser.py"
    kl = tmp_path / "killlog"
    body = (
        'kill() { echo "$@" >> "%s"; }\n'        # any signal at all is logged
        'ps() { echo "/py %s u" ; }\n'           # a matching process exists...
        'pgrep() { echo 33333; }\n'              # ...and a scan WOULD find it
        'sleep() { :; }\n'
        '_HELPER_FULL="%s"\nVPN_BROWSER_PIDFILE="%s"\n'     # pidfile path does NOT exist
        '_end_browser\necho DONE\n'
    ) % (str(kl), H, H, str(tmp_path / "nope.pid"))
    r = _sh(SRC_CONNECT, body)
    assert r.returncode == 0, r.stderr
    assert "DONE" in r.stdout
    killed = kl.read_text() if kl.exists() else ""
    assert "33333" not in killed, "must NOT pattern-reap a helper it never recorded (finding 3)"


def test_end_browser_skips_reused_pid_that_fails_argv(tmp_path):
    # PID-reuse guard (finding 9): the recorded PID is ALIVE but its argv is NOT our helper (the
    # pid was freed and reused by an unrelated process). _end_browser must NOT signal it --
    # pid_argv_has fails -> skip the kill entirely, only remove the pidfile.
    pf = tmp_path / "helper.pid"; pf.write_text("11111\n")
    kl = tmp_path / "killlog"
    body = (
        'kill() { case "$1" in -0) return 0 ;; *) echo "$@" >> "%s" ;; esac; }\n'   # -0: always alive
        'ps() { echo "/usr/bin/vim /some/other/file" ; }\n'    # argv is NOT our helper
        'sleep() { :; }\n'
        '_HELPER_FULL="/x/src/vpn_browser.py"\nVPN_BROWSER_PIDFILE="%s"\n'
        '_end_browser\necho DONE\n'
    ) % (str(kl), str(pf))
    r = _sh(SRC_CONNECT, body, strict=True)
    assert r.returncode == 0, r.stderr
    assert "DONE" in r.stdout
    killed = kl.read_text() if kl.exists() else ""
    assert "11111" not in killed, "must NOT signal a reused PID whose argv isn't our helper"
    assert not pf.exists(), "pidfile still removed"


def test_end_browser_no_set_e_abort_without_recorded_pid():
    # Under STRICT set -eu (the relaxed default masks errexit regressions): with no recorded PID
    # (pidfile absent), _end_browser must return cleanly (read-guard + early-return), not abort
    # the caller. The old landmine was a `_hp=$(_pids_matching ...)` whose failing pipeline
    # aborted a successful connect before Phase 2; the PID-only reaper removes that class.
    body = (
        'VPN_BROWSER_PIDFILE="/nonexistent/helper.pid"\n'         # no recorded PID
        '_HELPER_FULL="/x/src/vpn_browser.py"\n'
        'kill() { :; }\n'
        '_end_browser\necho DONE\n'
    )
    r = _sh(SRC_CONNECT, body, strict=True)
    assert r.returncode == 0, r.stderr
    assert "DONE" in r.stdout


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


# --- bin/openconnect-auto-sso: Phase-1 PID-capture flow (stub-openconnect integration) ---
# These run the REAL connect script end-to-end (it is always `set -eu`, so they double as the
# strict-mode check) with a stub `openconnect` + `sudo` + `nc` on PATH and a minimal config.
# The stub openconnect prints the eval-able COOKIE=... to stdout (Phase 1) / consumes the cookie
# (Phase 2), and spawns a stub helper that writes $VPN_BROWSER_PIDFILE (the connect script sets +
# exports it) and carries the vpn_browser.py marker in its argv so pid_argv_has confirms it. The
# stubs touch/rm liveness marker files (via TERM traps) so the test can see who was killed.
def _stub_connect_env(tmp_path):
    bindir = tmp_path / "sbin"; bindir.mkdir()
    mark = tmp_path / "mark"; mark.mkdir()
    oc_alive = mark / "oc_alive"
    helper_alive = mark / "helper_alive"
    phase2 = mark / "phase2"

    helper = bindir / "stub-helper"
    helper.write_text(
        "#!/bin/sh\n"
        "trap 'rm -f \"$HELPER_ALIVE\"; exit 0' TERM INT\n"
        "touch \"$HELPER_ALIVE\"\n"
        "[ -n \"${VPN_BROWSER_PIDFILE:-}\" ] && printf '%s\\n' \"$$\" > \"$VPN_BROWSER_PIDFILE\"\n"
        "case \"$2\" in\n"
        "  long) while :; do sleep 1; done ;;\n"
        "  *)    rm -f \"$HELPER_ALIVE\"; exit 0 ;;\n"    # short: pidfile then exit
        "esac\n")
    helper.chmod(0o755)

    oc = bindir / "openconnect"
    oc.write_text(
        "#!/bin/sh\n"
        # Real openconnect killed by a signal exits non-zero; mirror that (143) so the connect
        # script's auth-rc capture sees a FAILURE when the backstop TERMs a wedged openconnect.
        "trap 'rm -f \"$OC_ALIVE\"; exit 143' TERM INT\n"
        "case \" $* \" in\n"
        "  *' --authenticate '*)\n"
        "    touch \"$OC_ALIVE\"\n"
        "    case \"${STUB_MODE:-normal}\" in\n"
        "      normal)\n"
        "        sh \"$STUB_HELPER\" \"$HELPER_MARKER\" short >/dev/null 2>&1 &\n"
        "        sleep 0.5\n"
        "        printf 'COOKIE=abc123\\nHOST=test.example\\n"
        "CONNECT_URL=https://test.example/cb\\nFINGERPRINT=sha256:deadbeef\\n'\n"
        "        rm -f \"$OC_ALIVE\"; exit 0 ;;\n"
        "      slow)\n"
        "        sh \"$STUB_HELPER\" \"$HELPER_MARKER\" long >/dev/null 2>&1 &\n"
        "        while :; do sleep 1; done ;;\n"
        "      dead)\n"
        "        sh \"$STUB_HELPER\" \"$HELPER_MARKER\" short >/dev/null 2>&1 &\n"
        "        while :; do sleep 1; done ;;\n"
        "    esac ;;\n"
        "  *' --cookie-on-stdin '*)\n"
        "    cat >/dev/null 2>&1 || true\n"
        "    printf '%s\\n' \"$*\" > \"$PHASE2_MARKER\"\n"
        "    exit 0 ;;\n"
        "esac\n")
    oc.chmod(0o755)

    sudo = bindir / "sudo"
    sudo.write_text("#!/bin/sh\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n")
    sudo.chmod(0o755)

    nc = bindir / "nc"
    nc.write_text("#!/bin/sh\nexit 0\n")          # server always "reachable"
    nc.chmod(0o755)

    cfg = tmp_path / "config.toml"
    cfg.write_text('server = "test.example"\n')

    env = dict(os.environ)
    env["PATH"] = "%s:%s" % (bindir, env["PATH"])
    env["OC_AUTO_SSO_CONFIG"] = str(cfg)
    env["NC_BIN"] = str(nc)
    env["STUB_HELPER"] = str(helper)
    env["HELPER_MARKER"] = os.path.join(REPO, "src", "vpn_browser.py")
    env["OC_ALIVE"] = str(oc_alive)
    env["HELPER_ALIVE"] = str(helper_alive)
    env["PHASE2_MARKER"] = str(phase2)
    for leak in ("OC_CONNECT_TEST", "OC_PROJ", "OC_LAUNCHD"):
        env.pop(leak, None)
    return env, dict(oc_alive=oc_alive, helper_alive=helper_alive, phase2=phase2)


def _wait_gone(path, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if not path.exists():
            return True
        time.sleep(0.05)
    return not path.exists()


def test_phase1_normal_completion_captures_cookie_and_reaches_phase2(tmp_path):
    # Normal completion: the backgrounded openconnect's STDOUT is captured, eval'd (COOKIE set),
    # and Phase 2 runs with the captured FINGERPRINT/CONNECT_URL. rc 0, no stray helper. Proves
    # the whole set -eu flow does not abort on the happy path.
    env, m = _stub_connect_env(tmp_path)
    env["STUB_MODE"] = "normal"
    env["PHASE1_DEADLINE"] = "20"
    r = subprocess.run([CONNECT], capture_output=True, text=True, env=env,
                       stdin=subprocess.DEVNULL, timeout=30)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert m["phase2"].exists(), "Phase 2 never ran -> cookie capture/eval failed"
    p2 = m["phase2"].read_text()
    assert "--cookie-on-stdin" in p2
    assert "sha256:deadbeef" in p2, "captured FINGERPRINT not passed to Phase 2"
    assert "https://test.example/cb" in p2, "captured CONNECT_URL not passed to Phase 2"
    assert _wait_gone(m["oc_alive"]) and _wait_gone(m["helper_alive"])


def test_phase1_sigterm_kills_openconnect_and_helper(tmp_path):
    # launchd path: a SIGTERM to the SCRIPT (bootout) must TERM the backgrounded openconnect
    # (bootout doesn't) AND reap the helper, then exit -- so neither is orphaned. Big deadline so
    # the backstop can't be what kills them.
    env, m = _stub_connect_env(tmp_path)
    env["STUB_MODE"] = "slow"
    env["PHASE1_DEADLINE"] = "60"
    proc = subprocess.Popen([CONNECT], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, env=env, text=True)
    try:
        # Wait until Phase 1 is live (both stubs up).
        end = time.time() + 10
        while time.time() < end and not (m["oc_alive"].exists() and m["helper_alive"].exists()):
            time.sleep(0.05)
        assert m["oc_alive"].exists() and m["helper_alive"].exists(), "Phase 1 never came up"
        proc.terminate()                       # SIGTERM to the connect script
        proc.wait(timeout=15)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 130, "TERM trap should exit 130"
    assert _wait_gone(m["oc_alive"]), "openconnect left alive after SIGTERM (launchd orphan)"
    assert _wait_gone(m["helper_alive"]), "helper left alive after SIGTERM"


def test_phase1_slow_live_helper_not_killed_at_deadline(tmp_path):
    # A slow-but-live login (helper alive) must NEVER be killed by the backstop, even past the
    # deadline -- password + Duo can take minutes. openconnect stays alive; the script blocks on
    # `wait`. We confirm openconnect survives well past the deadline, then tear down.
    env, m = _stub_connect_env(tmp_path)
    env["STUB_MODE"] = "slow"
    env["PHASE1_DEADLINE"] = "2"
    proc = subprocess.Popen([CONNECT], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, env=env, text=True)
    try:
        end = time.time() + 10
        while time.time() < end and not m["oc_alive"].exists():
            time.sleep(0.05)
        assert m["oc_alive"].exists(), "Phase 1 never came up"
        time.sleep(4)                          # well past the 2s deadline
        assert m["oc_alive"].exists(), "backstop wrongly killed a slow-but-LIVE login"
        assert proc.poll() is None, "script exited though the login was still live"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    assert _wait_gone(m["oc_alive"]) and _wait_gone(m["helper_alive"])


def test_phase1_dead_helper_is_aborted_at_deadline(tmp_path):
    # A helper that died WITHOUT reaching the callback (recorded pid now dead) wedges openconnect
    # forever (its callback wait is select(NULL)). The backstop must fire at the deadline: TERM
    # openconnect so `wait` returns and Phase 1 fails loudly, instead of hanging forever.
    env, m = _stub_connect_env(tmp_path)
    env["STUB_MODE"] = "dead"
    env["PHASE1_DEADLINE"] = "2"
    r = subprocess.run([CONNECT], capture_output=True, text=True, env=env,
                       stdin=subprocess.DEVNULL, timeout=30)
    assert r.returncode != 0
    assert "Phase 1 stalled" in r.stderr, "backstop did not fire on a dead helper"
    assert "authentication failed" in r.stderr
    assert not m["phase2"].exists(), "must NOT reach Phase 2 on a failed auth"
    assert _wait_gone(m["oc_alive"]), "backstop should have TERMed the wedged openconnect"
