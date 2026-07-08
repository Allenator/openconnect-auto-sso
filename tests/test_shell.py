"""Tests for the POSIX-sh components, driven from pytest by shelling out to `sh`.

The scripts are sourced with a test-only guard (OC_*_TEST=1) that stops before their
main body, so individual functions can be exercised in isolation; file-touching helpers
are pointed at a temp dir via RESOLVER_DIR. vpn-teardown is run as a real subprocess with
a PATH-stubbed `pgrep` (never exercising its kill path, which would signal real PIDs).

macOS-only: the scripts use BSD `stat -f`, /etc/resolver, and utun conventions.
"""
import os
import subprocess
import sys

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
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env)


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


# --- vpn-teardown: arg dispatch + sweep guard (kill path deliberately not exercised) ---
def _run_teardown(args, tmp_path, pgrep_out, pgrep_rc):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "pgrep"
    stub.write_text("#!/bin/sh\n" + (("echo %s\n" % pgrep_out) if pgrep_out else "") + "exit %d\n" % pgrep_rc)
    stub.chmod(0o755)
    env = dict(os.environ, PATH="%s:%s" % (bindir, os.environ["PATH"]))
    return subprocess.run(["sh", TEARDOWN, *args], capture_output=True, text=True, env=env)


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
