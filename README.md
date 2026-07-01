# openconnect-auto-sso

Connect to browser-SSO (SAML) VPNs with
[`openconnect`](https://www.infradead.org/openconnect/), fixing three rough edges:

- the SSO login browser runs **unprivileged** — never as root;
- your identity-provider login is **remembered** between connects;
- a browser window appears **only when you actually need to log in** — otherwise the
  connect is silent;
- optional **split-tunnel** routing via [`vpn-slice`](https://github.com/dlenski/vpn-slice).

Everything site-specific (server, protocol, routes) lives in a gitignored `config.sh` —
nothing about any organization or identity provider is hardcoded.

## How it works

Two phases, so the browser is never privileged:

```
Phase 1  (as you, no sudo)
  openconnect --authenticate --external-browser=bin/vpn-browser <SERVER>
    → drives SSO in a small persistent-profile browser
    → prints COOKIE / CONNECT_URL / FINGERPRINT / RESOLVE

Phase 2  (sudo, no browser)
  echo "$COOKIE" | sudo openconnect --cookie-on-stdin --setuid $USER … <CONNECT_URL>
    → builds the tunnel from that cookie
```

The browser helper (`bin/vpn-browser`) renders the login in a QtWebEngine view backed by
a **named, on-disk profile** (so the IdP "stay signed in" cookie survives), and quits the
instant the flow reaches openconnect's `localhost:29786` loopback callback. It starts
**hidden** and only reveals a window if the login stalls waiting for you.

## Requirements

- `openconnect` ≥ 9 with external-browser SSO support (Cisco AnyConnect
  `single-sign-on-external-browser` and similar)
- [`uv`](https://docs.astral.sh/uv/) — manages the bundled PyQt6 browser helper
- `vpn-slice` — only if you use split-tunnel routing
- macOS (initial target; the helper is portable, the connect script is POSIX sh)

## Install

```sh
git clone <this-repo> && cd openconnect-auto-sso
uv sync                         # fetch the PyQt6 helper's dependencies
cp config.example.sh config.sh  # then edit SERVER (see below)
./install.sh                    # optional: symlink commands into ~/.local/bin
```

Without `install.sh`, run it in place with `./bin/openconnect-auto-sso`.

## Configuration

`config.sh` (gitignored) is sourced by the connect script:

| Variable       | Meaning                                                                 |
|----------------|-------------------------------------------------------------------------|
| `SERVER`       | VPN server hostname or URL. **Required.**                               |
| `PROTOCOL`     | openconnect protocol; blank = auto-detect (e.g. `anyconnect`, `gp`).    |
| `SPLIT_ROUTES` | `vpn-slice` args; blank = full tunnel. `%CIDR` excludes a subnet.       |
| `PROFILE_NAME` | Persistent browser-profile storage key. Usually leave as-is.            |
| `CALLBACK`     | openconnect's external-browser callback `host:port`. Rarely changed.    |

## Usage

```sh
openconnect-auto-sso        # or ./bin/openconnect-auto-sso
```

- **Warm cookie:** no window appears; you only see the `sudo` password prompt, then you're
  connected.
- **Cold / expired cookie:** a login window pops for your IdP (password, passkey, Duo,
  Touch ID …), closes itself when done, then the tunnel comes up.

Press `Ctrl-C` to disconnect.

## Split tunneling

Set `SPLIT_ROUTES` to the hosts/subnets that should go through the VPN; everything else
stays on your normal connection. Examples:

```sh
SPLIT_ROUTES="10.0.0.0/8"                        # one subnet via the VPN
SPLIT_ROUTES="10.0.0.0/8 wiki.corp.example.com"  # a subnet and a host
SPLIT_ROUTES="10.0.0.0/8 %100.64.0.0/10"         # …but exclude a range
```

The connect script resolves `vpn-slice` to an absolute path, since `sudo` (Phase 2)
usually doesn't have Homebrew on its `PATH`.

## Recipes

**Coexist with Tailscale.** Keep Tailscale's CGNAT range off the VPN by excluding it:

```sh
SPLIT_ROUTES="<your-vpn-subnets> %100.64.0.0/10"
```

With a split tunnel the VPN only claims your corporate routes, so Tailscale's default
route and `100.64.0.0/10` are untouched.

**Skip the sudo prompt.** Add a scoped `sudoers` rule (via `sudo visudo`) so only
`openconnect` can run without a password:

```
youruser ALL=(root) NOPASSWD: /opt/homebrew/bin/openconnect
```

## Security notes

- **The browser is never root.** Phase 1 runs as you; only Phase 2 (the tunnel) uses
  `sudo`, and it sheds root immediately via `--setuid $USER` once routes are set.
- **No secrets are stored by this tool.** Authentication uses your real IdP session
  (passkeys, Duo, Touch ID…). The only persisted item is the IdP's own browser cookie,
  in a profile under your user account — exactly like any browser's "stay signed in".
- **The server certificate is pinned** from Phase 1 (`--servercert`) when connecting.

## Troubleshooting

Environment knobs for the browser helper:

| Variable                 | Effect                                             |
|--------------------------|----------------------------------------------------|
| `VPN_BROWSER_SHOW=1`     | always show the window                             |
| `VPN_BROWSER_DEBUG=1`    | log lifecycle events to stderr                     |
| `VPN_BROWSER_IDLE_MS`    | idle ms before revealing the window (default 2500) |
| `VPN_BROWSER_TIMEOUT_MS` | overall safety timeout (default 180000)            |
| `OC_AUTO_SSO_CONFIG`     | path to an alternate config file                   |

## Scope

Targets openconnect servers that use the **external-browser SSO flow** (the
`localhost:29786` loopback callback). Any identity provider works — the helper is a
generic web view with no per-provider knowledge.

## License

MIT — see [LICENSE](LICENSE).
