#!/bin/sh
# install-autostart.sh -- connect the VPN automatically at login (opt-in).
#
# Separate from ./install.sh. Installs three pieces:
#   1. a per-user LaunchAgent (~/Library/LaunchAgents/openconnect-auto-sso.plist)
#      that runs the connect script at login and reconnects if the tunnel drops;
#   2. a root-owned teardown helper (/usr/local/libexec/openconnect-auto-sso/
#      vpn-teardown) that cleanly stops the tunnel on logout/uninstall -- the agent
#      runs as you and can't signal the root openconnect directly;
#   3. a NOPASSWD sudoers drop-in (/etc/sudoers.d/openconnect-auto-sso) so Phase 2's
#      `sudo openconnect` and the teardown helper never prompt (a LaunchAgent has no
#      TTY to type into).
#
# SECURITY: NOPASSWD on openconnect is effectively passwordless root, because
# openconnect runs a vpnc-script (its -s option) as root -- so it can run arbitrary
# commands as root. Any process running as you can then reach root without a
# prompt. Enable this only if you accept that trade for hands-off auto-connect.
# (The teardown helper is deliberately root-owned + self-contained, and install
# verifies its directory isn't user-writable, so its own NOPASSWD grant does NOT
# widen this -- it can't be pointed at attacker code.)
# Undo everything with: ./install-autostart.sh uninstall
#
# Usage: ./install-autostart.sh [install [--once] | uninstall | status]
#   install          connect at login AND reconnect on drop (KeepAlive)
#   install --once   connect once at login, do NOT auto-reconnect
set -eu

# $proj locates lib/common.sh AND the libexec/vpn-teardown helper this script installs as
# root with a NOPASSWD rule -- so it selects the SOURCE of a passwordless-root binary and
# must NOT come from the ambient environment during a real install. Always derive it from
# $0; honor the OC_PROJ override only when sourced by the test harness (OC_INSTALL_TEST=1),
# so a stray/poisoned OC_PROJ in the installer's env can't redirect it.
if [ "${OC_INSTALL_TEST:-}" = 1 ]; then
    proj="${OC_PROJ:-$(cd "$(dirname "$0")" && pwd)}"
else
    proj=$(cd "$(dirname "$0")" && pwd)
fi
. "$proj/lib/common.sh"   # LIBEXEC_DIR, TEARDOWN_BIN, THROTTLE_INTERVAL (single owner)
label="openconnect-auto-sso"
plist="$HOME/Library/LaunchAgents/$label.plist"
sudoers="/etc/sudoers.d/openconnect-auto-sso"
log="$HOME/Library/Logs/openconnect-auto-sso.log"
connect="$proj/bin/openconnect-auto-sso"
libexecdir="$LIBEXEC_DIR"
teardown_bin="$TEARDOWN_BIN"
teardown_src="$proj/libexec/vpn-teardown"
uid=$(id -u)
user=$(id -un)

find_bin() { command -v "$1" 2>/dev/null; }
xml_escape() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

# True if $1 is a safe home for a NOPASSWD-granted root binary: a real directory (not
# a symlink), root-owned, and NOT group/other-writable. A helper reachable through a
# user-writable OR symlinked path component could be swapped for arbitrary root code,
# hijacking the grant. `stat -f` is lstat (no -L), so it reports a symlink as mode
# `l...`, which we reject -- otherwise the writer (`install -d`) would follow the link
# to an unchecked target.
dir_is_safe() {
    _st=$(stat -f '%u %Sp' "$1" 2>/dev/null) || return 1
    _uid=${_st%% *}; _mode=${_st#* }
    [ "$_uid" = 0 ] || return 1                    # root-owned?
    case "$_mode" in
        l*)                 return 1 ;;            # symlink -> install -d follows it elsewhere
        ?????w*|????????w*) return 1 ;;            # group- or other-writable
    esac
    return 0
}

# Verify EVERY existing component of directory path $1 (from / down to the leaf) is a
# safe home for a NOPASSWD-granted root binary -- else it could be swapped for attacker
# code, hijacking the grant. A single loose or symlinked ancestor is enough, since
# unlink/rename is governed by the *parent's* write bit, not the leaf's. Deriving the
# chain from the path (rather than a hardcoded pair) keeps it from drifting off the
# real install location. Returns 0 if all-safe; prints the offender and returns 1 if not.
verify_safe_ancestors() {
    # Fail closed on a non-absolute (or empty) path -- the walk below assumes a leading /.
    case $1 in
        /*) ;;
        *)  echo "error: refusing to install under non-absolute path '$1'" >&2; return 1 ;;
    esac
    # Walk every existing component from / to the leaf and emit the first unsafe one. Run
    # the IFS/glob-sensitive split in a SUBSHELL: `set -f` stops each segment being
    # pathname-expanded (a stray glob char would otherwise validate the wrong paths) and
    # IFS=/ splits on separators -- both scoped to the subshell so the parent's options are
    # untouched. dir_is_safe is a function, so it's available here.
    _bad=$(
        set -f; IFS=/
        _acc=""
        for _seg in $1; do
            [ -n "$_seg" ] || continue          # skip the empty leading segment
            _acc="$_acc/$_seg"
            # -e follows symlinks, -L catches a dangling one; either must be vetted because
            # `install -d` writes through whatever the path resolves to.
            { [ -e "$_acc" ] || [ -L "$_acc" ]; } || continue
            dir_is_safe "$_acc" || { printf '%s' "$_acc"; break; }
        done
    )
    if [ -n "$_bad" ]; then
        echo "error: $_bad is not root-owned, is group/other-writable, or is a" >&2
        echo "       symlink; refusing to install a passwordless-root helper under it." >&2
        return 1
    fi
    return 0
}

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
    [ -f "$teardown_src" ] || { echo "error: $teardown_src missing" >&2; exit 1; }

    # The teardown helper gets a NOPASSWD rule, so every existing component of its
    # install path must be a safe directory (root-owned, NOT group/other-writable, not a
    # symlink) -- else it could be swapped for attacker code, hijacking the grant.
    verify_safe_ancestors "$libexecdir" || exit 1

    # Propagate a custom config location to the agent, so it resolves the SAME config
    # this precheck validates (the agent otherwise gets only PATH+HOME -> could resolve
    # a different, missing config and fail-loop).
    _cfg_env=""
    for _v in OC_AUTO_SSO_CONFIG XDG_CONFIG_HOME; do
        eval "_val=\${$_v:-}"
        [ -n "$_val" ] && _cfg_env="$_cfg_env
        <key>$_v</key>
        <string>$(xml_escape "$_val")</string>"
    done

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
    <integer>$THROTTLE_INTERVAL</integer>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>$(xml_escape "$apath")</string>
        <key>HOME</key>
        <string>$(xml_escape "$HOME")</string>$_cfg_env
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
    _did_sudoers=n; _did_plist=n; _did_libexec=n
    trap '
        [ "$_did_plist" = y ] && rm -f "$plist" 2>/dev/null || true
        [ "$_did_sudoers" = y ] && sudo rm -f "$sudoers" 2>/dev/null || true
        [ "$_did_libexec" = y ] && sudo rm -rf "$libexecdir" 2>/dev/null || true
        rm -f "$ptmp" "${stmp:-}" 2>/dev/null || true
    ' EXIT

    echo ">> installing the root teardown helper + sudoers rule (password once)..."
    # Root-owned teardown helper -- so its NOPASSWD grant can't be hijacked by
    # editing a user-writable file. Install it BEFORE the rule that references it.
    sudo install -d -o root -g wheel -m 0755 "$libexecdir"
    _did_libexec=y     # created the dir -> roll it back even if the copy below fails
    sudo install -o root -g wheel -m 0755 "$teardown_src" "$teardown_bin"
    echo "   $teardown_bin"

    # Two scoped NOPASSWD lines: openconnect (bring the tunnel up) and the teardown
    # helper (stop it cleanly on logout/uninstall). The teardown line pins its args to
    # the two intended forms, so a future flag/bug isn't auto-exposed to callers.
    stmp=$(mktemp)
    printf '# openconnect-auto-sso: passwordless sudo for the tunnel (up + teardown).\n' > "$stmp"
    printf '%s ALL=(root) NOPASSWD: %s\n' "$user" "$oc" >> "$stmp"
    printf '%s ALL=(root) NOPASSWD: %s "", %s --sweep\n' "$user" "$teardown_bin" "$teardown_bin" >> "$stmp"
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
    # Stop the AGENT first so its KeepAlive can't relaunch a fresh connect: bootout
    # sends the connect script SIGTERM, whose trap disconnects the tunnel cleanly via
    # the helper (its NOPASSWD rule is still present). Then a belt-and-suspenders
    # teardown catches any tunnel the trap didn't (e.g. a manual connect) BEFORE we
    # remove the helper + rule. (Doing teardown first would let KeepAlive relaunch in
    # the gap before bootout.)
    launchctl bootout "gui/$uid/$label" 2>/dev/null \
        || launchctl unload "$plist" 2>/dev/null || true
    if [ -x "$teardown_bin" ]; then
        echo ">> stopping any running tunnel (clean disconnect)..."
        sudo "$teardown_bin" 2>/dev/null || true
    fi
    if [ -f "$plist" ]; then rm -f "$plist" && echo "removed $plist"; fi
    if [ -e "$libexecdir" ]; then
        sudo rm -rf "$libexecdir" && echo "removed $libexecdir" || true
    fi
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
    echo ">> done."
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
    [ -x "$teardown_bin" ] && echo "teardown:    $teardown_bin (present)" || echo "teardown:    (not installed)"
    _tp=$(pgrep -x openconnect 2>/dev/null | tr '\n' ' ')
    [ -n "$_tp" ] && echo "tunnel:      openconnect $_tp (connected)" || echo "tunnel:      (not connected)"
    [ -f "$log" ] && echo "log:         $log" || echo "log:         (none yet) $log"
}

# The test harness sources this file to exercise dir_is_safe / verify_safe_ancestors in
# isolation; OC_INSTALL_TEST=1 skips the subcommand dispatch so sourcing has no side
# effects. Guard the dispatch with `if` rather than a top-level `return` -- `return` is
# invalid in an executed script and, under dash, a stray OC_INSTALL_TEST=1 in the env
# would make it silently exit without installing.
if [ "${OC_INSTALL_TEST:-}" != 1 ]; then
    case "${1:-install}" in
        install)   do_install "${2:-}" ;;
        uninstall) do_uninstall ;;
        status)    do_status ;;
        *) echo "usage: $0 [install [--once] | uninstall | status]" >&2; exit 2 ;;
    esac
fi
