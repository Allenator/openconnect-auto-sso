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
# Usage: ./install-autostart.sh [install|uninstall|status]
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

do_install() {
    [ -x "$connect" ] || { echo "error: $connect not found/executable" >&2; exit 1; }
    oc=$(find_bin openconnect) || { echo "error: openconnect not on PATH" >&2; exit 1; }

    # launchd's default PATH is minimal (no Homebrew), and the tool needs
    # openconnect / uv / vpn-slice. Build a PATH covering wherever they live.
    apath=""
    for t in openconnect uv vpn-slice; do
        p=$(find_bin "$t") || continue
        d=$(dirname "$p")
        case ":$apath:" in *":$d:"*) ;; *) apath="${apath:+$apath:}$d" ;; esac
    done
    apath="${apath:+$apath:}/usr/bin:/bin:/usr/sbin:/sbin"

    # 1) NOPASSWD sudoers drop-in -- validated with visudo before it is installed,
    #    so a mistake can never lock you out of sudo.
    echo ">> installing sudoers rule (asks for your password once)..."
    tmp=$(mktemp)
    printf '# openconnect-auto-sso: passwordless sudo for the VPN tunnel (Phase 2).\n' > "$tmp"
    printf '%s ALL=(root) NOPASSWD: %s\n' "$user" "$oc" >> "$tmp"
    if ! sudo visudo -cf "$tmp" >/dev/null 2>&1; then
        echo "error: sudoers syntax check failed; not installing" >&2
        rm -f "$tmp"; exit 1
    fi
    sudo install -m 0440 -o root -g wheel "$tmp" "$sudoers"
    rm -f "$tmp"
    echo "   $sudoers"

    # 2) LaunchAgent plist.
    mkdir -p "$(dirname "$plist")" "$(dirname "$log")"
    cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$connect</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>60</integer>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>$apath</string>
        <key>HOME</key>
        <string>$HOME</string>
    </dict>
    <key>StandardOutPath</key>
    <string>$log</string>
    <key>StandardErrorPath</key>
    <string>$log</string>
</dict>
</plist>
PLIST
    plutil -lint "$plist" >/dev/null || { echo "error: generated plist is invalid" >&2; exit 1; }
    echo "   $plist"

    # 3) Load it now (RunAtLoad connects immediately; it also loads at every login).
    launchctl bootout "gui/$uid/$label" 2>/dev/null || true
    if ! launchctl bootstrap "gui/$uid" "$plist" 2>/dev/null; then
        launchctl load -w "$plist"    # fallback for older launchctl
    fi
    echo ">> loaded. The tunnel connects now and at every login (reconnects on drop)."
    echo "   logs:   $log"
    echo "   status: ./install-autostart.sh status"
    echo "   stop:   ./install-autostart.sh uninstall"
}

do_uninstall() {
    launchctl bootout "gui/$uid/$label" 2>/dev/null \
        || launchctl unload "$plist" 2>/dev/null || true
    [ -f "$plist" ] && rm -f "$plist" && echo "removed $plist" || true
    if [ -f "$sudoers" ]; then
        echo ">> removing sudoers rule (asks for your password)..."
        sudo rm -f "$sudoers" && echo "removed $sudoers"
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
    install)   do_install ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    *) echo "usage: $0 [install|uninstall|status]" >&2; exit 2 ;;
esac
