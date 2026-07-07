#!/usr/bin/env python3
"""Parse an openconnect-auto-sso TOML config into shell-safe assignments.

Usage:  loadconfig.py CONFIG.toml   ->  prints  VAR=value  lines on stdout.

The connect script `eval`s the output. Values are shell-quoted here, and the
config is a declarative TOML file (never sourced), so a config file can't execute
code or inject shell -- unlike sourcing a *.sh config.

"What goes through the VPN" is a single `via_vpn` list; each entry's shape decides
how it's handled:

    @server               -> proxy the server-advertised domains (token; the
                             vpnc-slice wrapper expands it from CISCO_SPLIT_DNS /
                             CISCO_DEF_DOMAIN at connect)          -> PROXY_NAMES
    @internal             -> route the VPN's own pool subnet (vpn-slice -I)
    @splits               -> route the server's split-include subnets (vpn-slice -S)
    %CIDR   or  IP / CIDR -> a vpn-slice static route (or exclude, with %) -> SPLIT_ROUTES
    anything else (a name)-> a DNS name: /etc/resolver/<name> -> proxy    -> PROXY_NAMES
"""
import ipaddress
import shlex
import sys

try:
    import tomllib
except ModuleNotFoundError:  # tomllib needs 3.11; the project requires >= 3.12
    sys.stderr.write("config error: reading the config needs Python 3.12+ (tomllib)\n")
    sys.exit(2)

# scalar toml key -> (shell variable, kind)
SCALARS = {
    "server":             ("SERVER", "str"),
    "protocol":           ("PROTOCOL", "str"),
    "allow_incoming":     ("ALLOW_INCOMING", "bool"),
    "keepalive_host":     ("KEEPALIVE_HOST", "str"),
    "keepalive_interval": ("KEEPALIVE_INTERVAL", "int"),
    "proxy_port":         ("PROXY_PORT", "int"),
    "profile_name":       ("PROFILE_NAME", "str"),
    "callback":           ("CALLBACK", "str"),
}
KNOWN_KEYS = set(SCALARS) | {"via_vpn"}


def die(msg):
    sys.stderr.write("config error: " + msg + "\n")
    sys.exit(1)


def render_scalar(key, kind, val):
    if kind == "bool":
        if not isinstance(val, bool):
            die("'%s' must be true or false" % key)
        return "1" if val else "0"
    if kind == "int":
        if isinstance(val, bool) or not isinstance(val, int):
            die("'%s' must be an integer" % key)
        return str(val)
    # str
    if not isinstance(val, str):
        die("'%s' must be a string" % key)
    return val


def is_ip_or_cidr(entry):
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False


def classify_via_vpn(val):
    """Split via_vpn into PROXY_NAMES / SPLIT_ROUTES / ROUTE_INTERNAL / ROUTE_SPLITS."""
    if isinstance(val, str):
        val = [val]
    if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
        die("'via_vpn' must be a string or a list of strings")
    proxy_names = []
    split_routes = []
    route_internal = False
    route_splits = False
    for raw in val:
        entry = raw.strip()
        if not entry:
            continue
        if entry == "@server":
            proxy_names.append(entry)      # a token; the wrapper expands it at connect
        elif entry == "@internal":
            route_internal = True
        elif entry == "@splits":
            route_splits = True
        elif entry.startswith("@"):
            die("unknown via_vpn token '%s' (expected @server, @internal, @splits)" % entry)
        elif entry.startswith("%") or is_ip_or_cidr(entry):
            split_routes.append(entry)     # vpn-slice static route ('%' = exclude)
        else:
            proxy_names.append(entry)      # a DNS name -> /etc/resolver + proxy
    return proxy_names, split_routes, route_internal, route_splits


def main(argv):
    if len(argv) != 2:
        die("usage: loadconfig.py CONFIG.toml")
    try:
        with open(argv[1], "rb") as fh:
            cfg = tomllib.load(fh)
    except FileNotFoundError:
        die("no such file: " + argv[1])
    except OSError as e:
        die(str(e))
    except tomllib.TOMLDecodeError as e:
        die("invalid TOML: " + str(e))

    unknown = [k for k in cfg if k not in KNOWN_KEYS]
    if unknown:
        die("unknown key(s): " + ", ".join(sorted(unknown)))
    if not cfg.get("server"):
        die("'server' is required")

    lines = [
        "%s=%s" % (var, shlex.quote(render_scalar(key, kind, cfg[key])))
        for key, (var, kind) in SCALARS.items()
        if key in cfg
    ]

    proxy_names, split_routes, route_internal, route_splits = \
        classify_via_vpn(cfg.get("via_vpn", []))
    lines.append("PROXY_NAMES=%s" % shlex.quote(",".join(proxy_names)))
    lines.append("SPLIT_ROUTES=%s" % shlex.quote(" ".join(split_routes)))
    lines.append("ROUTE_INTERNAL=%s" % ("1" if route_internal else "0"))
    lines.append("ROUTE_SPLITS=%s" % ("1" if route_splits else "0"))

    sys.stdout.write("\n".join(lines))
    if lines:
        sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)
