# openconnect-auto-sso

Connect to browser-SSO (SAML) VPNs with
[`openconnect`](https://www.infradead.org/openconnect/), fixing three rough edges:

- the SSO login browser runs **unprivileged** — never as root;
- your identity-provider login is **remembered** between connects;
- a browser window appears **only when you actually need to log in** — otherwise the
  connect is silent;
- optional **split-tunnel** routing — by subnet *or* by DNS name (a name's traffic is
  routed to wherever it resolves) — via [`vpn-slice`](https://github.com/dlenski/vpn-slice).

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
  echo "$COOKIE" | sudo openconnect --cookie-on-stdin … <CONNECT_URL>
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
uv sync             # fetch the browser helper's deps (+ dev tools like pytest; --no-dev to skip)
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
| `via_vpn` | list | Everything that should go through the VPN, in one list; each entry's shape decides how it's handled (see below). `[]` = full tunnel. |
| `proxy_port` | int | Loopback port for the DNS-routing proxy (default `45353`); only used when `via_vpn` contains a name or `@server`. |
| `allow_incoming` | bool | `true` allows incoming from the VPN (no pf firewall) so iCloud Private Relay keeps working. |
| `keepalive_host` | string | Host to ping through the tunnel to avoid idle-disconnects. `"@dns"` auto-targets the VPN's own pushed DNS server (recommended); or a specific in-VPN host. `""` = off. |
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

`via_vpn` is the single list of everything that should go through the VPN; everything
else stays on your normal connection. Each entry's **shape** decides how it's handled:

| Entry | Example | What it does |
|-------|---------|--------------|
| DNS name (bare) | `example.com`, `host.corp.example.com` | Resolve it via the VPN's DNS **and** route every IP it answers with through the tunnel. A macOS `/etc/resolver` **suffix** match — `example.com` covers `example.com` *and* all its subdomains; a full host covers just that host. |
| IP or CIDR | `10.0.0.0/8`, `10.1.2.3` | A static route through the VPN. |
| `%CIDR` | `%100.64.0.0/10` | **Exclude** that range from the VPN. |
| `@server` | | Proxy whatever split-DNS domains the server advertises (`CISCO_SPLIT_DNS` / default domain) — so you needn't name them. |
| `@internal` | | Also route the VPN's own pool subnet, server-pushed (`vpn-slice -I`). |
| `@splits` | | Also route the server's split-include subnets, if any (`vpn-slice -S`). |

```toml
via_vpn = ["10.0.0.0/8"]                               # one subnet via the VPN
via_vpn = ["10.0.0.0/8", "wiki.corp.example.com"]      # a subnet and a host-by-name
via_vpn = ["corp.example.com", "%100.64.0.0/10"]       # a whole domain, minus a range
via_vpn = ["@server", "@internal"]                     # whatever the server advertises
```

An empty list (`via_vpn = []`) is a **full tunnel** — everything goes through the VPN and
no proxy or `/etc/resolver` files are created.

### How name-based routing works

Naming a host or domain does two things at once: its DNS *and* its traffic go through the
VPN. On connect, each name gets a macOS `/etc/resolver/<name>` file pointing at a small
loopback DNS proxy (`src/dnsroute.py`, started as root by the wrapper). The proxy forwards
those lookups to the VPN's own DNS servers and, for **every** IP each answer returns, adds
a host route out the tunnel device — installed *before* the DNS answer is handed back, so
even the very first packet takes the tunnel. So a load-balanced or rotating host gets a
route for whatever IP it actually resolves to — you don't have to know or hardcode its
addresses. On disconnect the proxy is stopped and the resolver files are removed (a
reconnect replaces the proxy rather than stacking a second one); the injected routes
vanish with the tunnel interface.

Two guard rails: the proxy **never routes the VPN gateway's own IP** through the tunnel
(the gateway carries the tunnel itself — even when the gateway's hostname falls under a
proxied domain, as it typically does); and the connect script **sweeps leftover resolver
files** at startup (they're tagged with an `# openconnect-auto-sso` marker, so only this
tool's own files are ever touched) — a straggler from a crashed teardown would otherwise
point its domains at a proxy that no longer exists.

> **Resolver-bypass caveat.** A route is injected only for lookups that go through the
> **system resolver**. An app that does its own DoH/DoT — e.g. a browser with "Secure DNS"
> on — bypasses `/etc/resolver`, so no route is added for names it resolves itself. For
> those destinations, put a **CIDR** in `via_vpn` (a static route needs no DNS).

The connect script resolves `vpn-slice` to an absolute path, since `sudo` (Phase 2)
usually doesn't have Homebrew on its `PATH`.

## Keeping an idle tunnel alive

Many VPN servers disconnect a tunnel that carries no traffic (openconnect reports
`Received server disconnect: ... 'Idle Timeout'`). In split-tunnel mode that happens
easily, since only your routed subnets generate traffic. Set `keepalive_host` to a host
that is reachable **inside** the VPN — i.e. one covered by `via_vpn` (or anything, in
full-tunnel mode) — and the connect script pings it every `keepalive_interval` seconds
while connected, stopping automatically on disconnect. The easiest choice is
`keepalive_host = "@dns"`, which auto-targets the VPN's own pushed DNS server — always
routed and always up, so you don't have to name it.

## Recipes

**Coexist with Tailscale.** Keep Tailscale's CGNAT range off the VPN by excluding it:

```toml
via_vpn = ["<your-vpn-subnets-or-names>", "%100.64.0.0/10"]
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

## Start automatically at login

To bring the tunnel up at login and keep it up, `install-autostart.sh` installs a
per-user **LaunchAgent**, a small **root-owned teardown helper**, and the NOPASSWD
`sudoers` rule they need (a launchd job has no terminal to type a password into):

Run `./install.sh` first so a config exists — `install` refuses to load an agent that
would just fail-loop with no config.

```sh
./install-autostart.sh install         # connect at login + reconnect on drop
./install-autostart.sh install --once  # connect once at login, no auto-reconnect
./install-autostart.sh status          # loaded? last exit code?
./install-autostart.sh uninstall       # remove the agent + the sudoers rule
tail -f ~/Library/Logs/openconnect-auto-sso.log
```

The agent runs in your GUI session (`Aqua`), so a **warm** cookie connects silently
while a **cold** one still pops the SSO window at login. By default it reconnects if
the tunnel drops (throttled). Note that a *persistent* failure — no network, or an
SSO login you keep dismissing — also retries on that throttle, re-popping the login;
use `--once` (or `uninstall`) if that's not what you want.

Because the agent runs as you but the tunnel runs as root, it can't signal openconnect
directly. The teardown helper closes that gap: on **logout** the connect script calls
it (via a scoped NOPASSWD rule) to send openconnect a clean disconnect, and `uninstall`
stops a running tunnel the same way before removing anything — so neither strands a root
tunnel with leftover routes/DNS. (If openconnect is ever `SIGKILL`ed instead — e.g. a
crash — that clean path is skipped; a stray `/etc/resolver/<name>` can then block the
next connect until you `sudo rm` it, which the startup sweep points out.)

> **Security.** The `sudoers` rule grants passwordless `sudo openconnect`, and
> openconnect can run arbitrary commands as root via its `-s` vpnc-script option — so
> it is effectively passwordless root for any process running as you. That is the price
> of unattended auto-connect; `uninstall` removes it. (The second NOPASSWD entry, for
> the teardown helper, does **not** widen this: the helper is root-owned and
> self-contained — it only signals the recorded openconnect PID, so it can't be pointed
> at attacker code the way a user-writable script could.) Prefer to keep the prompt?
> Skip this and connect manually (see *Skip the sudo prompt* above).

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
| `VPN_BROWSER_IDLE_MS`    | idle ms before revealing the window (default 3500) |
| `VPN_BROWSER_TIMEOUT_MS` | overall safety timeout (default 300000)            |
| `OC_AUTO_SSO_CONFIG`     | path to an alternate config file                   |
| `OC_DUMP`                | dump the server-advertised env vars to this file   |

## Scope

Targets openconnect servers that use the **external-browser SSO flow** (the
`localhost:29786` loopback callback). Any identity provider works — the helper is a
generic web view with no per-provider knowledge.

## License

MIT — see [LICENSE](LICENSE).
