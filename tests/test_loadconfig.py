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


def test_scalar_with_space_is_shell_quoted():
    # A server value with a space must come back quoted so the eval'ing shell can't
    # word-split it.
    r = _run_cli('server = "a b"\n')
    assert r.returncode == 0, r.stderr
    assert "SERVER='a b'" in r.stdout
