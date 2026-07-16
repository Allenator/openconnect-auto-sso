#!/usr/bin/env python3
"""Persistent-profile SSO browser for `openconnect --external-browser`.

openconnect launches this with the identity-provider login URL as argv[1]. We
render it in a QtWebEngine view backed by a NAMED, on-disk profile so the IdP
"stay signed in" cookie persists across connects, and we quit as soon as the
flow reaches openconnect's loopback callback (CALLBACK).

The window stays hidden while the SSO keeps making progress: if a warm cookie
carries the login straight through to the callback, no window is ever shown. A
window is revealed only when the flow goes idle on a page that needs you
(login / MFA).

Environment (all optional; set by bin/vpn-browser / the connect script):
  PROFILE_NAME            Qt persistent-profile storage key (default: openconnect-auto-sso)
  CALLBACK                host:port openconnect listens on (default: localhost:29786)
  VPN_BROWSER_SHOW=1      always show the window (debugging)
  VPN_BROWSER_IDLE_MS     idle ms before checking whether to reveal (default: 3500)
  VPN_BROWSER_TIMEOUT_MS  orphan-cleanup backstop in ms (default: 300000). The
                          connect script normally ends us once auth completes;
                          this only fires if we're left orphaned. Keep it well
                          above the longest plausible interactive login.
  VPN_BROWSER_DEBUG=1     log lifecycle events to stderr
"""
import ipaddress
import os
import signal
import subprocess
import sys
import time
import urllib.parse

# PyQt6 is imported lazily inside main()'s fail-loud guard (see B1/12), NOT at module
# top. An ImportError here (missing venv / no system PyQt6) would fire before main() ever
# runs -> fail_parent() would never be called -> openconnect wedges on its callback wait
# for ~420s. Deferring the import lets that ImportError reach main()'s `except
# BaseException: fail_parent(...)` so openconnect dies loudly instead. It also keeps the
# pure helpers below importable (for the unit tests) on a box without PyQt6.

APP_NAME = "openconnect-auto-sso"

# Reveal the window (as a fallback) after this many idle rounds settled on the SAME
# URL even when the interactivity heuristic sees nothing: the heuristic is main-frame
# only and blind to iframe / shadow-DOM / position:fixed controls, so a login page
# built that way would otherwise wait invisibly forever (feeding the B1 wedge).
REVEAL_AFTER_IDLE_ROUNDS = 3
IDLE_MS_FLOOR = 250        # never let VPN_BROWSER_IDLE_MS=0 turn the idle timer into a busy-loop
FINISH_GRACE_MS = 1500     # callback self-close: let Chromium durably commit the cookie
TERM_GRACE_MS = 1500       # SIGTERM (connect-script cleanup): same, before we exit
SIGNAL_PUMP_MS = 200       # tick the interpreter so a pending SIGTERM is serviced promptly

# Hold the profile for the whole process lifetime so it outlives the page.
_profile = None


def env_int(name, default):
    """Parse an integer env var, falling back to `default` for a missing / empty /
    non-numeric value instead of raising. A bad VPN_BROWSER_* var must not crash us
    before the QApplication exists -- openconnect would then block forever on its
    loopback-callback select() (it never watches this helper). See B1.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    # Clamp to signed int32 (B11): these values feed QTimer.singleShot / QTimer.start,
    # whose underlying C++ int OverflowErrors at the boundary for anything out of range.
    return max(-2**31, min(2**31 - 1, val))


def parse_callback(spec):
    host, _, port = spec.partition(":")
    try:
        port = int(port) if port else 29786
    except (TypeError, ValueError):
        port = 29786       # a malformed CALLBACK port must default, not crash (B1)
    return (host or "localhost"), port


def is_host_loopback(host):
    """True for any spelling of the loopback host (localhost / 127.0.0.0/8 / ::1).

    `localhost` is special-cased (it's a name, not an IP). Everything else is parsed as
    an IP address so a look-alike hostname -- 127.evil.com, which a `startswith("127.")`
    string test would wrongly accept -- is rejected (B2). A non-IP or empty host raises
    ValueError and is treated as not-loopback.
    """
    h = (host or "").strip().lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def is_callback(url, host, port):
    """True when `url` is openconnect's loopback callback.

    openconnect actually listens on ::1 (in6addr_loopback) and advertises the callback
    as some spelling of localhost, but the IdP may redirect to a different spelling
    (127.0.0.1 / ::1 / localhost). So when the configured host is itself loopback,
    treat ANY loopback spelling on the right port as the callback -- otherwise a
    ::1 redirect is missed and finish() (self-close + cookie flush) never fires. A
    custom non-loopback CALLBACK host still requires an exact host match.
    """
    if url.port() != port:
        return False
    if url.host().lower() == (host or "").lower():
        return True
    return is_host_loopback(host) and is_host_loopback(url.host())


def is_allowed_url(url_str):
    """Only http/https logins may be loaded. The SSO URL comes from the (possibly
    hostile / MITM'd) gateway; a file:// -- or any non-web -- scheme could read the
    on-disk cookie DB. See B4. Refusing unknown schemes is fail-closed.

    Uses stdlib urllib (not QUrl) so it needs no Qt import at module load time -- this
    runs before Qt is imported inside main() (B12) and in the PyQt6-free unit tests.
    """
    try:
        scheme = urllib.parse.urlsplit(url_str).scheme
    except ValueError:
        return False
    return scheme.lower() in ("http", "https")


def _comm_is_openconnect(comm):
    """True if a `ps -o comm=` value (a name or an absolute path) is openconnect."""
    return "openconnect" in (comm or "").strip().lower()


def _identify_parent():
    """Return (ppid, is_openconnect). openconnect posix_spawn()s us directly and
    bin/vpn-browser exec's python in place, so at startup getppid() IS the openconnect
    that is now blocked in select() awaiting the loopback callback. We verify that
    before ever signaling it, so a manual/dev run (parent = a shell) is never killed.
    """
    ppid = os.getppid()
    if ppid <= 1:
        return ppid, False
    try:
        out = subprocess.run(["ps", "-p", str(ppid), "-o", "comm="],
                             capture_output=True, text=True, timeout=2).stdout
    except Exception:
        return ppid, False
    return ppid, _comm_is_openconnect(out)


def reveal_decision(has_input, cur_url, prev_url, prev_rounds,
                    threshold=REVEAL_AFTER_IDLE_ROUNDS):
    """Pure decision for on_idle. Returns (action, new_url, new_rounds) where action
    is 'reveal' or 'wait'.

    Reveal at once if the page has a visible interactive element. Otherwise count
    consecutive idle rounds on the SAME url and reveal once they reach `threshold`
    (the B3 fallback for the heuristic's blind spots). A url change resets the count,
    so a healthy warm flow -- which keeps navigating toward the callback -- never trips
    the fallback and stays hidden.
    """
    if has_input:
        return ("reveal", cur_url, prev_rounds)
    rounds = prev_rounds + 1 if cur_url == prev_url else 1
    if rounds >= threshold:
        return ("reveal", cur_url, rounds)
    return ("wait", cur_url, rounds)


def set_activation_policy(app, policy):
    """macOS: 0 = Regular (Dock icon), 1 = Accessory (no Dock icon).

    No-op on non-macOS or non-cocoa platforms.
    """
    if sys.platform != "darwin" or app.platformName() != "cocoa":
        return
    try:
        import ctypes
        import ctypes.util

        objc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("objc"))
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.objc_msgSend.restype = ctypes.c_void_p
        objc.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        cls = objc.objc_getClass(b"NSApplication")
        shared = objc.objc_msgSend(cls, objc.sel_registerName(b"sharedApplication"))
        objc.objc_msgSend.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
        objc.objc_msgSend(shared, objc.sel_registerName(b"setActivationPolicy:"), policy)
    except Exception:
        pass


def main(argv):
    if len(argv) < 2 or not argv[1]:
        print("usage: vpn_browser.py <url>", file=sys.stderr)
        return 2
    login_url = argv[1]

    # Identify our parent up front (before Qt can crash): if it is openconnect, we can
    # fail Phase 1 LOUDLY on our own errors. openconnect awaits the loopback callback in
    # select(...,NULL) -- no timeout -- and never watches this helper, so any death of
    # ours that doesn't deliver the callback would otherwise wedge `openconnect
    # --authenticate` (and the connect script's auth capture) forever. See B1.
    parent_pid, parent_is_oc = _identify_parent()

    def fail_parent(reason):
        # Re-check getppid() at signal time: only signal while openconnect is STILL our
        # live parent. If Phase 1 already finished, openconnect has exited and we've been
        # reparented (getppid() != parent_pid) -- signaling then would be pointless and,
        # worse, could hit a reused PID. This makes the SIGTERM safe.
        if parent_is_oc and parent_pid > 1 and os.getppid() == parent_pid:
            # Signal FIRST, then log (B13). openconnect is blocked in select(...,NULL)
            # awaiting this SIGTERM; a stalled or closed stderr must never delay it, so the
            # os.kill() precedes the print() (which can block on a full/gone pipe).
            try:
                os.kill(parent_pid, signal.SIGTERM)
            except OSError:
                pass
            print("[vpn-browser] aborting openconnect (pid %d): %s" % (parent_pid, reason),
                  file=sys.stderr, flush=True)

    # B4: the login URL comes from the (possibly hostile) gateway. Refuse anything but
    # http/https before we spin up Qt -- a file:// URL could read the on-disk cookie DB.
    if not is_allowed_url(login_url):
        print("error: refusing non-http(s) SSO login URL: %r" % login_url, file=sys.stderr)
        fail_parent("refused non-http(s) login URL")
        return 3

    profile_name = os.environ.get("PROFILE_NAME") or APP_NAME
    cb_host, cb_port = parse_callback(os.environ.get("CALLBACK") or "localhost:29786")
    show_always = os.environ.get("VPN_BROWSER_SHOW") == "1"
    idle_ms = max(IDLE_MS_FLOOR, env_int("VPN_BROWSER_IDLE_MS", 3500))   # 0 would busy-loop (B5d)
    hard_ms = env_int("VPN_BROWSER_TIMEOUT_MS", 300000)
    debug = os.environ.get("VPN_BROWSER_DEBUG") == "1"
    t0 = time.monotonic()

    def log(*a):
        if debug:
            print("[vpn-browser +%.1fs]" % (time.monotonic() - t0), *a,
                  file=sys.stderr, flush=True)

    # Any fatal error while standing Qt up (bad display, profile path, construction)
    # would exit us non-zero and wedge openconnect's callback wait -- so signal the
    # parent on the way out. The connect-script deadline backstops a death so early we
    # can't even reach here.
    try:
        # B12: import Qt HERE, inside the fail-loud guard, not at module top. If the venv
        # is missing and system python3 lacks PyQt6, the ImportError now lands in the
        # `except BaseException` below -> fail_parent() aborts openconnect loudly, instead
        # of the import blowing up before main() and wedging the callback wait ~420s.
        # QtWebEngine must be imported before the QApplication is constructed.
        global QApplication, QWebEngineProfile, QWebEnginePage, QWebEngineSettings
        global QWebEngineView, QNetworkCookie, QUrl, QTimer, QStandardPaths
        from PyQt6.QtWebEngineWidgets import QWebEngineView
        from PyQt6.QtWebEngineCore import (
            QWebEngineProfile, QWebEnginePage, QWebEngineSettings)
        from PyQt6.QtNetwork import QNetworkCookie
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import QUrl, QTimer, QStandardPaths
        return _run(argv, login_url, profile_name, cb_host, cb_port, show_always,
                    idle_ms, hard_ms, log, fail_parent)
    except BaseException:
        fail_parent("fatal error starting the SSO browser")
        raise


def _run(argv, login_url, profile_name, cb_host, cb_port, show_always,
         idle_ms, hard_ms, log, fail_parent):
    app = QApplication([argv[0]])
    app.setApplicationName(APP_NAME)
    # Deliberately NO setOrganizationName: with an org name set, Qt derives the
    # profile path as <org>/<app>/... -- i.e. a same-name-nested
    # openconnect-auto-sso/openconnect-auto-sso/... We pin the storage path
    # explicitly below instead of relying on that derivation.
    # Start as a background (accessory) app so nothing appears while hidden.
    set_activation_policy(app, 0 if show_always else 1)

    global _profile
    _profile = QWebEngineProfile(profile_name)     # named -> on-disk
    # Pin the on-disk location to a flat <appdata>/<APP_NAME>/QtWebEngine/<profile>
    # so cookie persistence doesn't depend on Qt's app/org-name path derivation
    # (which nests, and could shift across Qt versions and silently orphan the
    # saved session). GenericDataLocation is the app/org-independent base
    # (~/Library/Application Support on macOS, ~/.local/share on Linux).
    base = QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.GenericDataLocation)
    storage = os.path.join(base, APP_NAME, "QtWebEngine", profile_name)
    # 0o700: the cookie DB under here is credential-equivalent (it holds the persisted
    # SSO session). mode= only affects a freshly created dir and is subject to umask, so
    # chmod too -- enforce it on a dir that pre-existed with looser permissions. (B5c)
    os.makedirs(storage, mode=0o700, exist_ok=True)
    try:
        os.chmod(storage, 0o700)
    except OSError:
        pass
    _profile.setPersistentStoragePath(storage)
    _profile.setCachePath(storage)
    _profile.setPersistentCookiesPolicy(
        QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
    )
    # B4: don't let web content reach file:// URLs -- the cookie DB lives on local disk.
    # (TLS is left at Qt's secure default, which rejects certificate errors.)
    _profile.settings().setAttribute(
        QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)
    log("profile storage:", storage)

    view = QWebEngineView()
    view.setPage(QWebEnginePage(_profile, view))
    view.setWindowTitle("VPN sign-in")
    view.resize(480, 720)

    done = {"v": False}          # callback reached -> success, self-closing
    asked_to_stop = {"v": False}  # SIGTERM from the connect script -> expected shutdown
    hard_timer = {"t": None}     # orphan-cleanup backstop; do_reveal() stops it (B9)

    def flush_cookies():
        # A no-op delete forces the cookie store to sync to disk.
        _profile.cookieStore().deleteCookie(QNetworkCookie())

    def finish():
        if done["v"]:
            return
        done["v"] = True
        log("callback reached; flushing cookies and quitting")
        flush_cookies()
        # Chromium batches cookie commits (~30s); give the just-earned session cookie
        # time to land on disk before we quit. See B2.
        QTimer.singleShot(FINISH_GRACE_MS, app.quit)

    # Not every server uses the localhost callback (some complete the SSO
    # server-side), so we can't always self-close -- the connect script ends us
    # once Phase 1 finishes. Periodically sync cookies to disk so the persistent
    # session survives that termination whenever it happens.
    flusher = QTimer()
    flusher.timeout.connect(flush_cookies)
    flusher.start(3000)

    # Keep the interpreter ticking so a Python signal handler (on_sigterm) is serviced
    # promptly while Qt's C++ event loop is otherwise blocked. See B2.
    pump = QTimer()
    pump.timeout.connect(lambda: None)
    pump.start(SIGNAL_PUMP_MS)

    # B2: the connect script now sends SIGTERM and WAITS for us, instead of a
    # fire-and-forget kill that could drop the cookie the login just produced. On
    # SIGTERM: flush and linger briefly so Chromium durably commits it, then quit.
    def on_sigterm(_signum, _frame):
        if asked_to_stop["v"]:
            return
        asked_to_stop["v"] = True
        log("SIGTERM: flushing cookies, exiting shortly")
        flush_cookies()
        QTimer.singleShot(TERM_GRACE_MS, app.quit)

    signal.signal(signal.SIGTERM, on_sigterm)

    # B1: if we quit WITHOUT having reached the callback and WITHOUT the connect script
    # telling us to stop (window closed, hard-timeout fired, or an unexpected quit),
    # Phase 1 will never get its callback -- so fail openconnect loudly rather than let
    # it block forever.
    def on_about_to_quit():
        if not done["v"] and not asked_to_stop["v"]:
            fail_parent("SSO browser closed before authentication completed")
    app.aboutToQuit.connect(on_about_to_quit)

    idle = QTimer()
    idle.setSingleShot(True)
    idle_state = {"url": None, "rounds": 0}

    # A warm SSO flow transits blank/redirect pages that momentarily look idle.
    # Only reveal the window when the current page actually has something to
    # interact with (a visible input/button/link), so those transients stay hidden.
    NEEDS_INPUT_JS = (
        "(function(){var s=document.querySelectorAll("
        "'input:not([type=hidden]),textarea,select,button,[role=button],a[href]');"
        "for(var i=0;i<s.length;i++){var e=s[i],r=e.getBoundingClientRect();"
        "if(r.width>4&&r.height>4&&e.offsetParent!==null)return true;}"
        "return false;})()"
    )

    def do_reveal():
        if done["v"] or view.isVisible():
            return
        log("revealing window for interaction")
        # B9: the user is now actively logging in (a password + Duo push can take
        # minutes). Stop the orphan-cleanup hard timeout so a legitimately slow login is
        # never killed mid-flow. A truly stuck helper is still bounded by the connect
        # script's _end_browser / PHASE1_DEADLINE backstops.
        if hard_timer["t"] is not None:
            hard_timer["t"].stop()
        set_activation_policy(app, 0)     # become a normal app for interaction
        view.show()
        view.raise_()
        view.activateWindow()

    def on_idle():
        if done["v"] or view.isVisible():
            return

        def decide(has_input):
            if done["v"] or view.isVisible():
                return
            action, url, rounds = reveal_decision(
                bool(has_input), view.url().toString(),
                idle_state["url"], idle_state["rounds"])
            idle_state["url"], idle_state["rounds"] = url, rounds
            if action == "reveal":
                if not has_input:
                    log("idle %d rounds on %s; revealing as a fallback" % (rounds, url))
                do_reveal()
            else:
                log("idle on a non-interactive page (%s); staying hidden" % url)
                idle.start(idle_ms)     # still looks transient; keep waiting

        try:
            view.page().runJavaScript(NEEDS_INPUT_JS, decide)
        except Exception:
            do_reveal()

    idle.timeout.connect(on_idle)

    def bump():
        # Progress happened (navigation / load). Postpone the reveal check.
        if not view.isVisible() and not done["v"]:
            idle.start(idle_ms)

    def on_url(url):
        # B3: urlChanged fires at navigation START -- and on a FAILED nav that merely
        # points at the callback host. Do NOT finish() here: a premature quit before
        # openconnect actually receives the callback wedges Phase 1. Just keep feeding the
        # reveal timer; finish() is gated on a SUCCESSFUL load in on_load_finished below.
        log("navigated:", url.toString())
        bump()

    def on_load_finished(ok):
        # B3: self-close only once the callback URL has actually LOADED SUCCESSFULLY.
        # A failed callback load (ok is False) must NOT finish -- openconnect either
        # already captured the token (then the connect script's _end_browser ends us on
        # the success path) or never got it (quitting early would wedge Phase 1). Either
        # way, not finishing here is the safe choice.
        if ok and is_callback(view.url(), cb_host, cb_port):
            finish()

    view.urlChanged.connect(on_url)
    view.loadFinished.connect(on_load_finished)
    view.page().loadProgress.connect(lambda _p: bump())

    log("loading", login_url)
    view.load(QUrl(login_url))
    if show_always:
        view.show()
    else:
        idle.start(idle_ms)               # hidden; reveal only if the flow stalls

    # Orphan backstop only: the connect script ends us when Phase 1 finishes.
    # This must never fire during a legitimate (possibly slow) interactive login, so
    # do_reveal() stops it the moment we show the window for interaction (B9). A
    # non-positive timeout disables it (rather than quitting instantly). (B5d)
    #
    # In show mode (VPN_BROWSER_SHOW=1, a debug knob) the window is shown up front, so
    # on_idle/do_reveal never run and the timer would never be stopped -- it would then
    # fire mid-login and (via on_about_to_quit -> fail_parent) SIGTERM openconnect. Skip
    # arming it entirely when showing: a human is watching, and _end_browser / the connect
    # script's PHASE1_DEADLINE still bound a truly stuck helper. (B9)
    if hard_ms > 0 and not show_always:
        ht = QTimer()
        ht.setSingleShot(True)
        ht.timeout.connect(app.quit)
        ht.start(hard_ms)
        hard_timer["t"] = ht
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
