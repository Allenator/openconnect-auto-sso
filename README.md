# openconnect-auto-sso

Connect to browser-SSO (SAML) VPNs with
[`openconnect`](https://www.infradead.org/openconnect/), fixing three rough edges:

- the SSO browser runs **unprivileged** — never as root;
- your identity-provider login is **remembered** between connects;
- a browser window appears **only when you actually need to log in** (otherwise the
  connect is silent);
- optional **split-tunnel** routing via [`vpn-slice`](https://github.com/dlenski/vpn-slice).

Everything site-specific (server, protocol, routes) lives in a gitignored `config.sh` —
nothing about any organization or identity provider is hardcoded.

> **Status:** work in progress.

## Requirements

- `openconnect` ≥ 9 with external-browser SSO support
- [`uv`](https://docs.astral.sh/uv/) (manages the bundled PyQt6 browser helper)
- `vpn-slice` (only if you use split-tunnel routing)
- macOS (initial target)

## Quick start

```sh
cp config.example.sh config.sh     # then edit SERVER (and SPLIT_ROUTES if desired)
./bin/openconnect-auto-sso
```

## How it works

Two phases, so the browser is never privileged:

1. **Authenticate as you** — `openconnect --authenticate --external-browser=<helper>`
   drives the SSO login in a small persistent-profile browser and prints a session cookie.
2. **Connect as root** — `sudo openconnect --cookie-on-stdin …` builds the tunnel from that
   cookie, with no browser involved.

_Fuller documentation (config reference, recipes, security notes) is added in a later
milestone._
