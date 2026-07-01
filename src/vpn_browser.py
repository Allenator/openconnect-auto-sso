#!/usr/bin/env python3
"""Persistent-profile SSO browser for `openconnect --external-browser`.

openconnect launches this with the identity-provider login URL as argv[1]. We
render it in a QtWebEngine view backed by a NAMED, on-disk profile so the IdP
"stay signed in" cookie persists across connects, and we quit as soon as the
flow reaches openconnect's loopback callback (CALLBACK) -- at that point
openconnect already has the SSO token, so the browser is no longer needed.

Environment (set by bin/vpn-browser; both optional):
  PROFILE_NAME  Qt persistent-profile storage key   (default: openconnect-auto-sso)
  CALLBACK      host:port openconnect listens on     (default: localhost:29786)

This M1 baseline is always-visible; a later milestone makes the window appear
only when the login actually needs interaction.
"""
import os
import sys

# QtWebEngine must be imported before the QApplication is constructed.
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage
from PyQt6.QtNetwork import QNetworkCookie
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QUrl, QTimer

APP_NAME = "openconnect-auto-sso"

# Hold the profile for the whole process lifetime so it outlives the page it
# backs (otherwise Qt warns "profile released but page not deleted" on teardown).
_profile = None


def parse_callback(spec):
    host, _, port = spec.partition(":")
    return (host or "localhost"), int(port or "29786")


def is_callback(url, host, port):
    """True when `url` is openconnect's loopback token callback."""
    if url.port() != port:
        return False
    if url.host() == host:
        return True
    # treat localhost and 127.0.0.1 as equivalent
    return host == "localhost" and url.host() in ("localhost", "127.0.0.1")


def main(argv):
    if len(argv) < 2 or not argv[1]:
        print("usage: vpn_browser.py <url>", file=sys.stderr)
        return 2
    login_url = argv[1]

    profile_name = os.environ.get("PROFILE_NAME") or APP_NAME
    cb_host, cb_port = parse_callback(os.environ.get("CALLBACK") or "localhost:29786")

    app = QApplication([argv[0]])
    app.setApplicationName(APP_NAME)      # stable persistent-storage path
    app.setOrganizationName(APP_NAME)

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

    def finish():
        if done["v"]:
            return
        done["v"] = True
        # Force the cookie store to sync to disk even for a very short-lived
        # (warm-cookie) run: a no-op delete triggers the flush. Then quit.
        _profile.cookieStore().deleteCookie(QNetworkCookie())
        QTimer.singleShot(800, app.quit)

    def on_url(url):
        if is_callback(url, cb_host, cb_port):
            finish()

    view.urlChanged.connect(on_url)
    view.load(QUrl(login_url))
    view.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
