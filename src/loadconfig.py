#!/usr/bin/env python3
"""Parse an openconnect-auto-sso TOML config into shell-safe assignments.

Usage:  loadconfig.py CONFIG.toml   ->  prints  VAR=value  lines on stdout.

The connect script `eval`s the output. Values are shell-quoted here, and the
config is a declarative TOML file (never sourced), so a config file can't execute
code or inject shell -- unlike sourcing a *.sh config.
"""
import shlex
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    sys.stderr.write("config error: reading the config needs Python 3.11+ (tomllib)\n")
    sys.exit(2)

# toml key -> (shell variable, kind)
SCHEMA = {
    "server":             ("SERVER", "str"),
    "protocol":           ("PROTOCOL", "str"),
    "split_routes":       ("SPLIT_ROUTES", "list_space"),
    "vpn_domains":        ("VPN_DOMAINS", "list_comma"),
    "route_internal":     ("ROUTE_INTERNAL", "bool"),
    "route_splits":       ("ROUTE_SPLITS", "bool"),
    "allow_incoming":     ("ALLOW_INCOMING", "bool"),
    "keepalive_host":     ("KEEPALIVE_HOST", "str"),
    "keepalive_interval": ("KEEPALIVE_INTERVAL", "int"),
    "profile_name":       ("PROFILE_NAME", "str"),
    "callback":           ("CALLBACK", "str"),
}


def die(msg):
    sys.stderr.write("config error: " + msg + "\n")
    sys.exit(1)


def render(key, kind, val):
    if kind == "bool":
        if not isinstance(val, bool):
            die("'%s' must be true or false" % key)
        return "1" if val else "0"
    if kind == "int":
        if isinstance(val, bool) or not isinstance(val, int):
            die("'%s' must be an integer" % key)
        return str(val)
    if kind == "str":
        if not isinstance(val, str):
            die("'%s' must be a string" % key)
        return val
    # list_space / list_comma
    if isinstance(val, str):
        val = [val]
    if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
        die("'%s' must be a string or a list of strings" % key)
    return (" " if kind == "list_space" else ",").join(val)


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

    unknown = [k for k in cfg if k not in SCHEMA]
    if unknown:
        die("unknown key(s): " + ", ".join(sorted(unknown)))
    if not cfg.get("server"):
        die("'server' is required")

    lines = [
        "%s=%s" % (var, shlex.quote(render(key, kind, cfg[key])))
        for key, (var, kind) in SCHEMA.items()
        if key in cfg
    ]
    sys.stdout.write("\n".join(lines))
    if lines:
        sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)
