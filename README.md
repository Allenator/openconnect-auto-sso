# openconnect-auto-sso

Connect to browser-SSO (SAML) VPNs with
[`openconnect`](https://www.infradead.org/openconnect/), fixing three rough edges:

- the SSO login browser runs **unprivileged** — never as root;
- your identity-provider login is **remembered** between connects;
- a browser window appears **only when you actually need to log in** — otherwise the
  connect is silent;
- optional **split-tunnel** routing via [`vpn-slice`](https://github.com/dlenski/vpn-slice).

Everything site-specific (server, protocol, routes) lives in a config file outside the
repo (`~/.config/openconnect-auto-sso/config.toml`) — nothing about any organization or
identity provider is hardcoded.

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
uv sync             # fetch the PyQt6 helper's dependencies
./install.sh        # symlink commands into ~/.local/bin AND seed the config
# then edit ~/.config/openconnect-auto-sso/config.toml (SERVER, etc.)
```

Without `install.sh`, run it in place with `./bin/openconnect-auto-sso`.

## Configuration

Config is a TOML file at `~/.config/openconnect-auto-sso/config.toml` (outside the repo;
override with `$OC_AUTO_SSO_CONFIG`, or drop a `config.toml` in the repo for dev). It is
**parsed** (validated and quoted) — never sourced — so a config file can't execute code.

| Key | Type | Meaning |
|-----|------|---------|
| `server` | string | VPN server hostname or URL. **Required.** |
| `protocol` | string | openconnect protocol; `""` auto-detects (e.g. `"anyconnect"`, `"gp"`). |
| `split_routes` | list | Subnets/hosts routed through the VPN; a `%CIDR` entry excludes one. `[]` = full tunnel. |
| `vpn_domains` | list | Domains resolved via the VPN's DNS (split DNS, à la Tailscale MagicDNS); resolvers pulled from the connection. The token `"@server"` also scopes whatever domains the VPN advertises (`CISCO_SPLIT_DNS`/default domain). |
| `route_internal` | bool | Also route the VPN's own subnet, server-pushed (`vpn-slice -I`). |
| `route_splits` | bool | Also route the server's split-include subnets, if any (`vpn-slice -S`). |
| `allow_incoming` | bool | `true` allows incoming from the VPN (no pf firewall) so iCloud Private Relay keeps working. |
| `keepalive_host` | string | Host to ping through the tunnel to avoid idle-disconnects; must be reachable inside the VPN. `""` = off. |
| `keepalive_interval` | int | Seconds between keepalive pings (default 30). |
| `profile_name` | string | Qt persistent-profile storage key. Usually leave default. |
| `callback` | string | openconnect external-browser callback `host:port`. Rarely changed. |

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

Set `split_routes` to the hosts/subnets that should go through the VPN; everything else
stays on your normal connection. Examples:

```toml
split_routes = ["10.0.0.0/8"]                          # one subnet via the VPN
split_routes = ["10.0.0.0/8", "wiki.corp.example.com"] # a subnet and a host
split_routes = ["10.0.0.0/8", "%100.64.0.0/10"]        # …but exclude a range
```

The connect script resolves `vpn-slice` to an absolute path, since `sudo` (Phase 2)
usually doesn't have Homebrew on its `PATH`.

## Keeping an idle tunnel alive

Many VPN servers disconnect a tunnel that carries no traffic (openconnect reports
`Received server disconnect: ... 'Idle Timeout'`). In split-tunnel mode that happens
easily, since only your routed subnets generate traffic. Set `keepalive_host` to a host
that is reachable **inside** the VPN — i.e. one covered by `split_routes` (or anything, in
full-tunnel mode) — and the connect script pings it every `keepalive_interval` seconds
while connected, stopping automatically on disconnect. An internal DNS server is a good,
stable choice; just make sure its subnet is in `split_routes` so the ping goes through the
tunnel.

## Recipes

**Coexist with Tailscale.** Keep Tailscale's CGNAT range off the VPN by excluding it:

```toml
split_routes = ["<your-vpn-subnets>", "%100.64.0.0/10"]
```

With a split tunnel the VPN only claims your corporate routes, so Tailscale's default
route and `100.64.0.0/10` are untouched.

**Keep iCloud Private Relay working.** macOS disables Private Relay when it sees a
default-route rule, a DNS takeover, *or* a packet-filter change. A route-only split
tunnel avoids the first two, but `vpn-slice`'s default "block incoming" firewall adds a
pf anchor that trips the third. Set `allow_incoming = true` (passes `vpn-slice -i`) to drop
that firewall so Private Relay stays on — weigh it against letting VPN hosts reach open
ports on your machine.

That firewall can also *leak*: `vpn-slice` appends its anchor to `/etc/pf.conf` and
sometimes fails to remove it on teardown, leaving the anchor loaded on every boot — which
keeps Private Relay disabled even with no VPN connected. `openconnect-auto-sso` **warns at
startup** if it finds such a leftover and offers to clean it (strip the line and reload
pf). `allow_incoming = true` avoids creating it in the first place.

**Skip the sudo prompt.** Add a scoped `sudoers` rule (via `sudo visudo`) so only
`openconnect` can run without a password:

```
youruser ALL=(root) NOPASSWD: /opt/homebrew/bin/openconnect
```

## Security notes

- **The browser is never root.** Phase 1 runs as you; only Phase 2 (the tunnel) uses
  `sudo`. openconnect keeps root for the tunnel's lifetime — on macOS this is required so
  that *disconnecting* can cleanly restore your routes and DNS. (Dropping privileges with
  `--setuid` makes teardown run unprivileged, which fails to restore them and can strand
  your network.)
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
