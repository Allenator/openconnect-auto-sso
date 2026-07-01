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
  VPN_BROWSER_TIMEOUT_MS  overall safety timeout in ms (default: 180000)
  VPN_BROWSER_DEBUG=1     log lifecycle events to stderr
"""
import os
import sys
import time

# QtWebEngine must be imported before the QApplication is constructed.
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage
from PyQt6.QtNetwork import QNetworkCookie
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QUrl, QTimer

APP_NAME = "openconnect-auto-sso"

# Hold the profile for the whole process lifetime so it outlives the page.
_profile = None


def parse_callback(spec):
    host, _, port = spec.partition(":")
    return (host or "localhost"), int(port or "29786")


def is_callback(url, host, port):
    if url.port() != port:
        return False
    if url.host() == host:
        return True
    return host == "localhost" and url.host() in ("localhost", "127.0.0.1")


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

    profile_name = os.environ.get("PROFILE_NAME") or APP_NAME
    cb_host, cb_port = parse_callback(os.environ.get("CALLBACK") or "localhost:29786")
    show_always = os.environ.get("VPN_BROWSER_SHOW") == "1"
    idle_ms = int(os.environ.get("VPN_BROWSER_IDLE_MS") or "3500")
    hard_ms = int(os.environ.get("VPN_BROWSER_TIMEOUT_MS") or "180000")
    debug = os.environ.get("VPN_BROWSER_DEBUG") == "1"
    t0 = time.monotonic()

    def log(*a):
        if debug:
            print("[vpn-browser +%.1fs]" % (time.monotonic() - t0), *a,
                  file=sys.stderr, flush=True)

    app = QApplication([argv[0]])
    app.setApplicationName(APP_NAME)      # stable persistent-storage path
    app.setOrganizationName(APP_NAME)
    # Start as a background (accessory) app so nothing appears while hidden.
    set_activation_policy(app, 0 if show_always else 1)

    global _profile
    _profile = QWebEngineProfile(profile_name)     # named -> on-disk
    _profile.setPersistentCookiesPolicy(
        QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
    )

    view = QWebEngineView()
    view.setPage(QWebEnginePage(_profile, view))
    view.setWindowTitle("VPN sign-in")
    view.resize(480, 720)

    done = {"v": False}

    def flush_cookies():
        # A no-op delete forces the cookie store to sync to disk.
        _profile.cookieStore().deleteCookie(QNetworkCookie())

    def finish():
        if done["v"]:
            return
        done["v"] = True
        log("callback reached; flushing cookies and quitting")
        flush_cookies()
        QTimer.singleShot(800, app.quit)

    # Not every server uses the localhost callback (some complete the SSO
    # server-side), so we can't always self-close -- the connect script ends us
    # once Phase 1 finishes. Periodically sync cookies to disk so the persistent
    # session survives that termination whenever it happens.
    flusher = QTimer()
    flusher.timeout.connect(flush_cookies)
    flusher.start(3000)

    idle = QTimer()
    idle.setSingleShot(True)

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
            if has_input:
                do_reveal()
            else:
                log("idle on a non-interactive page (%s); staying hidden"
                    % view.url().toString())
                idle.start(idle_ms)     # still a transient; keep waiting

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
        if is_callback(url, cb_host, cb_port):
            finish()
        else:
            log("navigated:", url.toString())
            bump()

    view.urlChanged.connect(on_url)
    view.page().loadProgress.connect(lambda _p: bump())

    log("loading", login_url)
    view.load(QUrl(login_url))
    if show_always:
        view.show()
    else:
        idle.start(idle_ms)               # hidden; reveal only if the flow stalls

    QTimer.singleShot(hard_ms, app.quit)  # safety net
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
