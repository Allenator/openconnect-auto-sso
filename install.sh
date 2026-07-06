#!/bin/sh
# Symlink the openconnect-auto-sso commands into a bin directory on your PATH.
# Usage: ./install.sh [BINDIR]   (default: ~/.local/bin)
set -eu

proj=$(cd "$(dirname "$0")" && pwd)
bindir="${1:-$HOME/.local/bin}"
mkdir -p "$bindir"

for cmd in openconnect-auto-sso vpn-browser; do
    ln -sf "$proj/bin/$cmd" "$bindir/$cmd"
    echo "linked $bindir/$cmd -> $proj/bin/$cmd"
done

# Seed the config in the standard external location if it's not there yet.
conf="${XDG_CONFIG_HOME:-$HOME/.config}/openconnect-auto-sso/config.toml"
if [ -f "$conf" ]; then
    echo "config exists at $conf"
else
    mkdir -p "$(dirname "$conf")"
    cp "$proj/config.example.toml" "$conf"
    echo "created $conf -- edit server (and other settings) before connecting"
fi

case ":$PATH:" in
    *":$bindir:"*) ;;
    *) echo "note: $bindir is not on your PATH — add it to use the commands by name" >&2 ;;
esac
