#!/bin/sh
# install-autostart.sh -- connect the VPN automatically at login (opt-in).
#
# Separate from ./install.sh. Installs two pieces:
#   1. a per-user LaunchAgent (~/Library/LaunchAgents/openconnect-auto-sso.plist)
#      that runs the connect script at login and reconnects if the tunnel drops;
#   2. a NOPASSWD sudoers drop-in (/etc/sudoers.d/openconnect-auto-sso) so Phase 2's
#      `sudo openconnect` never prompts -- a LaunchAgent has no TTY to type into.
#
# SECURITY: NOPASSWD on openconnect is effectively passwordless root, because
# openconnect runs a vpnc-script (its -s option) as root -- so it can run arbitrary
# commands as root. Any process running as you can then reach root without a
# prompt. Enable this only if you accept that trade for hands-off auto-connect.
# Undo everything with: ./install-autostart.sh uninstall
#
# Usage: ./install-autostart.sh [install [--once] | uninstall | status]
#   install          connect at login AND reconnect on drop (KeepAlive)
#   install --once   connect once at login, do NOT auto-reconnect
set -eu

proj=$(cd "$(dirname "$0")" && pwd)
label="openconnect-auto-sso"
plist="$HOME/Library/LaunchAgents/$label.plist"
sudoers="/etc/sudoers.d/openconnect-auto-sso"
log="$HOME/Library/Logs/openconnect-auto-sso.log"
connect="$proj/bin/openconnect-auto-sso"
uid=$(id -u)
user=$(id -un)

find_bin() { command -v "$1" 2>/dev/null; }
xml_escape() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

do_install() {
    [ -x "$connect" ] || { echo "error: $connect not found/executable" >&2; exit 1; }
    # A working config must exist first: otherwise RunAtLoad fails every login and
    # KeepAlive would respawn the failing connect forever. Fail loudly here instead.
    cfg="${OC_AUTO_SSO_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/openconnect-auto-sso/config.toml}"
    if [ ! -f "$cfg" ] && [ ! -f "$proj/config.toml" ]; then
        echo "error: no config found ($cfg)." >&2
        echo "       run ./install.sh (it seeds a config) and edit 'server' first." >&2
        exit 1
    fi
    oc=$(find_bin openconnect) || { echo "error: openconnect not on PATH" >&2; exit 1; }

    # launchd's default PATH is minimal (no Homebrew); the tool needs openconnect /
    # uv / vpn-slice. Build a PATH covering wherever they live.
    apath=""
    for t in openconnect uv vpn-slice; do
        p=$(find_bin "$t") || continue
        d=$(dirname "$p")
        case ":$apath:" in *":$d:"*) ;; *) apath="${apath:+$apath:}$d" ;; esac
    done
    apath="${apath:+$apath:}/usr/bin:/bin:/usr/sbin:/sbin"

    # KeepAlive: default reconnect-on-drop; `--once` connects at login only.
    if [ "${1:-}" = "--once" ]; then keepalive="false"; else keepalive="true"; fi

    # Build AND validate the plist in a temp file BEFORE touching sudoers, so a bad
    # plist (e.g. an XML metacharacter in a path) can never leave passwordless root
    # behind. Values are XML-escaped; the heredoc does no word-splitting, so spaces
    # and apostrophes in paths are fine.
    mkdir -p "$(dirname "$plist")" "$(dirname "$log")"
    ptmp=$(mktemp)
    cat > "$ptmp" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$(xml_escape "$label")</string>
    <key>ProgramArguments</key>
    <array>
        <string>$(xml_escape "$connect")</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <$keepalive/>
    <key>ThrottleInterval</key>
    <integer>300</integer>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>$(xml_escape "$apath")</string>
        <key>HOME</key>
        <string>$(xml_escape "$HOME")</string>
    </dict>
    <key>StandardOutPath</key>
    <string>$(xml_escape "$log")</string>
    <key>StandardErrorPath</key>
    <string>$(xml_escape "$log")</string>
</dict>
</plist>
PLIST
    if ! plutil -lint "$ptmp" >/dev/null; then
        echo "error: generated plist is invalid -- a path may contain an XML" >&2
        echo "       metacharacter (& < >): proj=$proj home=$HOME" >&2
        rm -f "$ptmp"; exit 1
    fi

    # Privileged step. Roll back BOTH the sudoers file and the plist if anything
    # below fails, so a partial install never leaves passwordless root with no agent.
    _did_sudoers=n; _did_plist=n
    trap '
        [ "$_did_plist" = y ] && rm -f "$plist" 2>/dev/null || true
        [ "$_did_sudoers" = y ] && sudo rm -f "$sudoers" 2>/dev/null || true
        rm -f "$ptmp" 2>/dev/null || true
    ' EXIT

    echo ">> installing sudoers rule (asks for your password once)..."
    stmp=$(mktemp)
    printf '# openconnect-auto-sso: passwordless sudo for the VPN tunnel (Phase 2).\n' > "$stmp"
    printf '%s ALL=(root) NOPASSWD: %s\n' "$user" "$oc" >> "$stmp"
    if ! sudo visudo -cf "$stmp" >/dev/null 2>&1; then
        echo "error: sudoers syntax check failed; not installing" >&2
        rm -f "$stmp"; exit 1
    fi
    sudo install -m 0440 -o root -g wheel "$stmp" "$sudoers"
    rm -f "$stmp"; _did_sudoers=y
    echo "   $sudoers"

    install -m 0644 "$ptmp" "$plist"; _did_plist=y
    echo "   $plist"

    launchctl bootout "gui/$uid/$label" 2>/dev/null || true
    if ! launchctl bootstrap "gui/$uid" "$plist" 2>/dev/null; then
        launchctl load -w "$plist"    # fallback for older launchctl
    fi

    trap - EXIT           # success: disarm rollback
    rm -f "$ptmp" 2>/dev/null || true
    if [ "$keepalive" = true ]; then
        echo ">> loaded. Connects now and at every login; reconnects on drop."
    else
        echo ">> loaded. Connects now and at every login (no auto-reconnect: --once)."
    fi
    echo "   logs:   $log"
    echo "   status: ./install-autostart.sh status"
    echo "   stop:   ./install-autostart.sh uninstall"
}

do_uninstall() {
    launchctl bootout "gui/$uid/$label" 2>/dev/null \
        || launchctl unload "$plist" 2>/dev/null || true
    if [ -f "$plist" ]; then rm -f "$plist" && echo "removed $plist"; fi
    if [ -f "$sudoers" ]; then
        echo ">> removing sudoers rule (asks for your password)..."
        # Check the removal explicitly: a failed `sudo rm` in an `&&` chain would be
        # exempt from `set -e` and silently leave the passwordless-root rule active.
        if sudo rm -f "$sudoers"; then
            echo "removed $sudoers"
        else
            echo "ERROR: could not remove $sudoers -- the passwordless-root rule is" >&2
            echo "       STILL ACTIVE. Remove it manually: sudo rm -f $sudoers" >&2
            exit 1
        fi
    fi
    echo ">> done. A tunnel that is currently up keeps running until it next exits."
}

do_status() {
    [ -f "$plist" ] && echo "LaunchAgent: $plist" || echo "LaunchAgent: (not installed)"
    if launchctl print "gui/$uid/$label" >/dev/null 2>&1; then
        echo "  loaded: yes"
        launchctl print "gui/$uid/$label" 2>/dev/null \
            | grep -E 'state =|last exit code|pid =' | sed 's/^ */  /'
    else
        echo "  loaded: no"
    fi
    [ -f "$sudoers" ] && echo "sudoers:     $sudoers (present)" || echo "sudoers:     (not installed)"
    [ -f "$log" ] && echo "log:         $log" || echo "log:         (none yet) $log"
}

case "${1:-install}" in
    install)   do_install "${2:-}" ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    *) echo "usage: $0 [install [--once] | uninstall | status]" >&2; exit 2 ;;
esac
