"""Unit tests for the pure logic in src/vpn_browser.py.

These cover only side-effect-free helpers -- callback detection, the SSO-URL scheme
guard, callback-spec / env-var parsing, the parent-identification predicate, and the
reveal-after-N-idle-rounds fallback decision. No QApplication, GUI, or network is
started (importing PyQt6 for QUrl is fine; the venv has it). The live SSO flow is the
user's end-to-end test, not this suite's.
"""
import vpn_browser as vb
from PyQt6.QtCore import QUrl


# --- parse_callback (CALLBACK spec -> host, port; malformed port must default) ---
def test_parse_callback_defaults():
    assert vb.parse_callback("localhost:29786") == ("localhost", 29786)
    assert vb.parse_callback("") == ("localhost", 29786)
    assert vb.parse_callback("myhost") == ("myhost", 29786)          # no port -> default
    assert vb.parse_callback(":8000") == ("localhost", 8000)          # no host -> default
    assert vb.parse_callback("1.2.3.4:5") == ("1.2.3.4", 5)


def test_parse_callback_bad_port_defaults_not_raises():
    # A malformed CALLBACK port must NOT raise pre-QApplication (that would wedge
    # openconnect's callback wait forever -- B1); it defaults instead.
    assert vb.parse_callback("host:notaport") == ("host", 29786)
    assert vb.parse_callback("host:") == ("host", 29786)


# --- env_int (guarded integer env parse: missing / empty / non-numeric -> default) ---
def test_env_int_valid(monkeypatch):
    monkeypatch.setenv("OC_TEST_INT", "1234")
    assert vb.env_int("OC_TEST_INT", 99) == 1234


def test_env_int_negative_is_kept(monkeypatch):
    # env_int only parses; range clamping (e.g. the idle-ms floor) is the caller's job.
    monkeypatch.setenv("OC_TEST_INT", "-5")
    assert vb.env_int("OC_TEST_INT", 99) == -5


def test_env_int_falls_back(monkeypatch):
    monkeypatch.delenv("OC_TEST_INT", raising=False)
    assert vb.env_int("OC_TEST_INT", 3500) == 3500           # missing
    monkeypatch.setenv("OC_TEST_INT", "")
    assert vb.env_int("OC_TEST_INT", 3500) == 3500           # empty
    monkeypatch.setenv("OC_TEST_INT", "abc")
    assert vb.env_int("OC_TEST_INT", 3500) == 3500           # non-numeric -> no raise
    monkeypatch.setenv("OC_TEST_INT", "12.5")
    assert vb.env_int("OC_TEST_INT", 3500) == 3500           # float string -> no raise


def test_env_int_clamps_to_int32(monkeypatch):
    # B11: values feed QTimer.singleShot / QTimer.start, whose C++ int OverflowErrors
    # outside signed int32. env_int must clamp so Qt never sees an out-of-range value.
    monkeypatch.setenv("OC_TEST_INT", str(2**40))
    assert vb.env_int("OC_TEST_INT", 0) == 2**31 - 1          # above max -> clamped
    monkeypatch.setenv("OC_TEST_INT", str(-(2**40)))
    assert vb.env_int("OC_TEST_INT", 0) == -2**31             # below min -> clamped
    monkeypatch.setenv("OC_TEST_INT", str(2**31 - 1))
    assert vb.env_int("OC_TEST_INT", 0) == 2**31 - 1          # exactly max -> unchanged
    monkeypatch.setenv("OC_TEST_INT", str(-2**31))
    assert vb.env_int("OC_TEST_INT", 0) == -2**31             # exactly min -> unchanged
    monkeypatch.setenv("OC_TEST_INT", "300000")
    assert vb.env_int("OC_TEST_INT", 0) == 300000            # in range -> passthrough


# --- is_host_loopback ---
def test_is_host_loopback():
    for h in ("localhost", "LOCALHOST", "127.0.0.1", "127.5.6.7", "::1"):
        assert vb.is_host_loopback(h), h
    for h in ("example.com", "10.0.0.1", "", None, "127a.0.0.1x"):
        assert not vb.is_host_loopback(h), h


def test_is_host_loopback_rejects_lookalike_hostnames():
    # B2: a `h.startswith("127.")` string test wrongly accepts these DNS names that are
    # NOT the loopback interface. Parsing as an IP rejects them (ValueError -> False).
    for h in ("127.evil.com", "127.0.0.1.evil.com", "127.0.0.1.nip.io",
              "localhost.evil.com", "127foo"):
        assert not vb.is_host_loopback(h), h
    # ...while every genuine loopback spelling is still accepted.
    for h in ("127.0.0.1", "127.255.255.254", "::1", "localhost"):
        assert vb.is_host_loopback(h), h


# --- is_callback (loopback-shape tolerant; B5b) ---
def _cb(url, host="localhost", port=29786):
    return vb.is_callback(QUrl(url), host, port)


def test_is_callback_localhost_and_127():
    assert _cb("http://localhost:29786/")
    assert _cb("http://127.0.0.1:29786/")


def test_is_callback_ipv6_loopback():
    # openconnect listens on ::1; a redirect to the [::1] spelling must still count,
    # otherwise finish() (self-close + cookie flush) never fires. This is the B5b fix.
    assert _cb("http://[::1]:29786/callback?code=abc")


def test_is_callback_wrong_port():
    assert not _cb("http://localhost:29785/")
    assert not _cb("http://127.0.0.1:1234/")


def test_is_callback_non_loopback_host_rejected():
    assert not _cb("https://evil.example:29786/")


def test_is_callback_rejects_lookalike_loopback_host():
    # B2: a look-alike host on the right port must NOT be mistaken for the loopback
    # callback -- otherwise finish() (self-close) could fire on an attacker-controlled
    # 127.evil.com redirect. The IP-parse in is_host_loopback closes that bypass.
    assert not _cb("http://127.evil.com:29786/callback?code=abc")
    assert not _cb("http://127.0.0.1.evil.com:29786/callback?code=abc")


def test_is_callback_custom_host_requires_exact_match():
    # A non-loopback CALLBACK host still demands an exact host match -- a stray loopback
    # redirect must not be mistaken for a custom-host callback.
    assert vb.is_callback(QUrl("http://vpn.corp:29786/"), "vpn.corp", 29786)
    assert not vb.is_callback(QUrl("http://127.0.0.1:29786/"), "vpn.corp", 29786)


# --- is_allowed_url (B4: only http/https logins) ---
def test_is_allowed_url_accepts_web_schemes():
    assert vb.is_allowed_url("http://vpn.example/login")
    assert vb.is_allowed_url("https://vpn.example/login")
    assert vb.is_allowed_url("HTTPS://vpn.example/login")     # scheme is case-insensitive


def test_is_allowed_url_rejects_dangerous_schemes():
    for u in ("file:///etc/passwd", "javascript:alert(1)", "ftp://x/y",
              "data:text/html,x", "//host/path", "not a url", ""):
        assert not vb.is_allowed_url(u), u


# --- _comm_is_openconnect (parent-identification predicate for the fail-loud gate) ---
def test_comm_is_openconnect():
    for c in ("openconnect", "/opt/homebrew/bin/openconnect", "OpenConnect\n"):
        assert vb._comm_is_openconnect(c), repr(c)
    for c in ("python", "/bin/zsh", "", None, "sh"):
        assert not vb._comm_is_openconnect(c), repr(c)


# --- reveal_decision (B3: reveal after N idle rounds on the same URL) ---
def test_reveal_decision_reveals_immediately_with_input():
    action, url, rounds = vb.reveal_decision(True, "https://idp/login", None, 0)
    assert action == "reveal" and url == "https://idp/login"


def test_reveal_decision_counts_rounds_then_reveals():
    # Same URL, no detected input: wait until the threshold, then reveal as a fallback
    # (the heuristic is blind to iframe/shadow/fixed controls).
    u = "https://idp/login"
    a, url, r = vb.reveal_decision(False, u, None, 0, threshold=3)
    assert (a, r) == ("wait", 1)
    a, url, r = vb.reveal_decision(False, u, url, r, threshold=3)
    assert (a, r) == ("wait", 2)
    a, url, r = vb.reveal_decision(False, u, url, r, threshold=3)
    assert (a, r) == ("reveal", 3)


def test_reveal_decision_url_change_resets_counter():
    # A healthy warm flow keeps navigating; each new URL resets the count so the
    # fallback never fires and the window stays hidden.
    a, url, r = vb.reveal_decision(False, "https://a", None, 0, threshold=3)
    assert (a, r) == ("wait", 1)
    a, url, r = vb.reveal_decision(False, "https://a", url, r, threshold=3)
    assert (a, r) == ("wait", 2)
    a, url, r = vb.reveal_decision(False, "https://b", url, r, threshold=3)  # navigated
    assert (a, url, r) == ("wait", "https://b", 1)                          # reset to 1


def test_reveal_decision_threshold_one_reveals_first_idle():
    a, _, r = vb.reveal_decision(False, "https://idp", None, 0, threshold=1)
    assert (a, r) == ("reveal", 1)


# --- write_own_pidfile: record our PID so the connect script reaps THIS run's helper (finding 8)
def test_write_own_pidfile_records_our_pid(tmp_path, monkeypatch):
    import os
    pf = tmp_path / "helper.pid"
    monkeypatch.setenv("VPN_BROWSER_PIDFILE", str(pf))
    vb.write_own_pidfile()
    assert pf.read_text().strip() == str(os.getpid())


def test_write_own_pidfile_noop_without_env(tmp_path, monkeypatch):
    # No env var -> no file written, and no exception (best-effort; must never stop the login).
    monkeypatch.delenv("VPN_BROWSER_PIDFILE", raising=False)
    vb.write_own_pidfile()   # must not raise
    assert not (tmp_path / "helper.pid").exists()


def test_write_own_pidfile_refuses_symlink_target(tmp_path, monkeypatch):
    # Finding 5: a pre-planted symlink at the pidfile path must NOT redirect our write to its
    # target. Unlink-first + O_NOFOLLOW replace the symlink with a fresh 0600 regular file and
    # write our PID there, leaving the pointed-at target untouched. (A plain open("w") would
    # follow the link and clobber the target -- the mutation this pins.)
    import os
    target = tmp_path / "target"
    target.write_text("ORIGINAL\n")
    link = tmp_path / "helper.pid"
    os.symlink(str(target), str(link))
    monkeypatch.setenv("VPN_BROWSER_PIDFILE", str(link))
    vb.write_own_pidfile()
    assert target.read_text() == "ORIGINAL\n", "must NOT follow the symlink to its target"
    assert not os.path.islink(str(link)), "planted symlink should be replaced by a real file"
    assert link.read_text().strip() == str(os.getpid())
    assert (link.stat().st_mode & 0o077) == 0, "pidfile must not be group/other-accessible"
