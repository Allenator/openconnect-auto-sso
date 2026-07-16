"""Tests for src/loadconfig.py (TOML config -> shell assignments).

Covers the via_vpn classifier (the security-critical part: a bad entry must be
rejected, never silently turned into a root-written /etc/resolver path or an unquoted
token in the root -s string), the hostname/IP validators, and the CLI's end-to-end
behavior (required key, unknown key, shell-quoting).
"""
import os
import subprocess
import sys
import tempfile

import pytest

import loadconfig

LOADCONFIG_PY = os.path.join(os.path.dirname(__file__), "..", "src", "loadconfig.py")


# --- classify_via_vpn --------------------------------------------------------
def test_bare_names_go_to_proxy_names():
    proxy, splits, internal, spl = loadconfig.classify_via_vpn(
        ["yale.edu", "ood-grace.ycrc.yale.edu"])
    assert proxy == ["yale.edu", "ood-grace.ycrc.yale.edu"]
    assert splits == []
    assert internal is False
    assert spl is False


def test_ip_and_cidr_go_to_split_routes():
    proxy, splits, _, _ = loadconfig.classify_via_vpn(["10.1.2.3", "10.178.0.0/16", "::1"])
    assert proxy == []
    assert splits == ["10.1.2.3", "10.178.0.0/16", "::1"]


def test_percent_prefix_is_an_exclude_route():
    _, splits, _, _ = loadconfig.classify_via_vpn(["%100.64.0.0/10"])
    assert splits == ["%100.64.0.0/10"]


def test_server_token_kept_for_wrapper_expansion():
    proxy, _, _, _ = loadconfig.classify_via_vpn(["@server"])
    assert proxy == ["@server"]


def test_internal_and_splits_tokens_set_flags():
    _, _, internal, spl = loadconfig.classify_via_vpn(["@internal", "@splits"])
    assert internal is True
    assert spl is True


def test_trailing_dot_fqdn_is_stripped():
    proxy, _, _, _ = loadconfig.classify_via_vpn(["yale.edu."])
    assert proxy == ["yale.edu"]


def test_underscore_labels_accepted():
    proxy, _, _, _ = loadconfig.classify_via_vpn(["_kerberos._tcp.corp", "my_service.corp"])
    assert proxy == ["_kerberos._tcp.corp", "my_service.corp"]


def test_string_is_treated_as_single_entry():
    proxy, _, _, _ = loadconfig.classify_via_vpn("yale.edu")
    assert proxy == ["yale.edu"]


def test_unknown_token_rejected():
    with pytest.raises(SystemExit):
        loadconfig.classify_via_vpn(["@bogus"])


def test_malformed_cidr_rejected_not_treated_as_name():
    # "10.0.0/8" is a typo'd subnet, not a hostname -- must fail loudly, not become a name.
    with pytest.raises(SystemExit):
        loadconfig.classify_via_vpn(["10.0.0/8"])


@pytest.mark.parametrize("bad", ["evil;rm -rf", "a b.corp", "../etc", "name$(id)", "-lead.corp"])
def test_metacharacter_name_rejected(bad):
    with pytest.raises(SystemExit):
        loadconfig.classify_via_vpn([bad])


def test_bad_percent_exclude_rejected():
    with pytest.raises(SystemExit):
        loadconfig.classify_via_vpn(["%notanip"])


# --- validators --------------------------------------------------------------
@pytest.mark.parametrize("good", ["a.b.c", "yale.edu", "_dmarc.example.com", "x-1.corp"])
def test_is_hostname_accepts(good):
    assert loadconfig.is_hostname(good)


@pytest.mark.parametrize("bad", ["bad!", "-lead.com", "trail-.com", "a/b", "a b", "", "x" * 260])
def test_is_hostname_rejects(bad):
    assert not loadconfig.is_hostname(bad)


@pytest.mark.parametrize("good", ["10.0.0.0/8", "1.2.3.4", "::1", "2001:db8::/32"])
def test_is_ip_or_cidr_accepts(good):
    assert loadconfig.is_ip_or_cidr(good)


@pytest.mark.parametrize("bad", ["10.0.0/8", "not-an-ip", "999.1.1.1"])
def test_is_ip_or_cidr_rejects(bad):
    assert not loadconfig.is_ip_or_cidr(bad)


# --- CLI end-to-end ----------------------------------------------------------
def _run_cli(toml_text):
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as fh:
        fh.write(toml_text)
        path = fh.name
    try:
        return subprocess.run([sys.executable, LOADCONFIG_PY, path],
                              capture_output=True, text=True)
    finally:
        os.unlink(path)


def test_valid_config_emits_expected_vars():
    r = _run_cli(
        'server = "access.yale.edu"\n'
        'via_vpn = ["yale.edu", "%100.64.0.0/10", "@internal"]\n'
        'allow_incoming = true\n'
    )
    assert r.returncode == 0, r.stderr
    out = dict(line.split("=", 1) for line in r.stdout.splitlines())
    assert out["SERVER"] == "access.yale.edu"
    assert out["ALLOW_INCOMING"] == "1"
    assert out["PROXY_NAMES"] == "yale.edu"
    assert out["SPLIT_ROUTES"] == "%100.64.0.0/10"   # shlex-safe, emitted bare
    assert out["ROUTE_INTERNAL"] == "1"
    assert out["ROUTE_SPLITS"] == "0"


def test_missing_server_fails():
    r = _run_cli('via_vpn = ["yale.edu"]\n')
    assert r.returncode == 1
    assert "server" in r.stderr


def test_unknown_key_fails():
    r = _run_cli('server = "x"\nsplit_routes = ["10.0.0.0/8"]\n')   # a removed key
    assert r.returncode == 1
    assert "unknown key" in r.stderr


def test_proxy_port_out_of_range_fails():
    r = _run_cli('server = "x"\nproxy_port = 70000\n')
    assert r.returncode == 1


def test_reconnect_timeout_emitted():
    r = _run_cli('server = "x"\nreconnect_timeout = 15\n')
    assert r.returncode == 0, r.stderr
    assert "RECONNECT_TIMEOUT=15" in r.stdout


def test_reconnect_timeout_zero_allowed():
    # 0 is meaningful: give up immediately and let a fresh connect take over.
    r = _run_cli('server = "x"\nreconnect_timeout = 0\n')
    assert r.returncode == 0, r.stderr
    assert "RECONNECT_TIMEOUT=0" in r.stdout


def test_reconnect_timeout_negative_rejected():
    r = _run_cli('server = "x"\nreconnect_timeout = -1\n')
    assert r.returncode == 1
    assert "reconnect_timeout" in r.stderr


def test_reconnect_timeout_non_integer_rejected():
    r = _run_cli('server = "x"\nreconnect_timeout = "30"\n')
    assert r.returncode == 1


def test_reconnect_timeout_absurdly_large_rejected():
    # openconnect parses this with atoi, so an out-of-range value overflows to a
    # non-positive int, which it reads as "give up at once" -- the opposite of the
    # "retry ~forever" a user writing a huge number intends. Reject it here instead.
    r = _run_cli('server = "x"\nreconnect_timeout = 99999999999999999999\n')
    assert r.returncode == 1


def test_absent_reconnect_timeout_emits_no_variable():
    # The connect script's launch-mode default (30 under KeepAlive / 300 under --once or
    # interactive) only works if loadconfig stays SILENT when the key is absent.
    r = _run_cli('server = "x"\n')
    assert r.returncode == 0, r.stderr
    assert "RECONNECT_TIMEOUT" not in r.stdout


def test_config_example_parses():
    # Guards against config.example.toml drifting from SCALARS/KNOWN_KEYS (a key added to
    # the example but not the schema would fail here with "unknown key").
    example = os.path.join(os.path.dirname(__file__), "..", "config.example.toml")
    r = subprocess.run([sys.executable, LOADCONFIG_PY, example],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_scalar_with_space_is_shell_quoted():
    # A server value with a space must come back quoted so the eval'ing shell can't
    # word-split it.
    r = _run_cli('server = "a b"\n')
    assert r.returncode == 0, r.stderr
    assert "SERVER='a b'" in r.stdout
