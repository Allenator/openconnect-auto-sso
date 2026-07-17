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

# OC_INSTALL_TEST=1 is a SOURCING-only seam for the test harness (it skips the dispatch at the
# bottom so sourcing has no side effects). If it leaks into a real EXECUTED run the installer
# would silently do nothing -- and a poisoned OC_PROJ could then redirect $proj (-> a foreign
# lib/common.sh and the libexec/vpn-teardown SOURCE that gets root-installed under a NOPASSWD
# rule). Refuse LOUDLY here, BEFORE sourcing anything from $proj. Executed: $0 is this script
# (basename install-autostart.sh -- openconnect never invokes it, so no renamed-symlink path);
# sourced with `.`: $0 stays the caller's ("sh" under the harness), so the seam is unaffected.
if [ "${OC_INSTALL_TEST:-}" = 1 ]; then
    case ${0##*/} in
        install-autostart.sh)
            echo "error: OC_INSTALL_TEST=1 is set but install-autostart.sh is being EXECUTED," >&2
            echo "       not sourced by the test harness -- refusing to silently no-op. Unset it." >&2
            exit 1 ;;
    esac
fi

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

# Per-component safety predicate for a NOPASSWD-root path. $2 = space-separated list of
# allowed owner UIDs. A component is safe iff it is owned by one of those UIDs, is NOT a
# symlink, and is NOT group/other-writable -- because a component another user can own,
# rename, replace, or symlink-redirect lets them swap in code that runs as root (or as the
# login-agent user, who reaches root via the NOPASSWD openconnect rule). `stat -f` is lstat
# (no -L), so a symlink shows mode `l...` and is rejected -- otherwise the writer (`install
# -d`) or executor would follow the link to an unchecked target. Fails closed if $1 can't be
# stat'd. The space-padded `case` avoids partial UID matches (" 100 " vs " 1000 ").
#
# LIMITATION: `stat -f %Sp` shows only POSIX mode bits, so this is blind to a macOS ACL
# (e.g. an `everyone allow write` ACE added via `chmod +a`, visible only under `ls -lde`).
# A dir could thus be ACL-writable while its mode bits look tight. Exploiting that needs the
# attacker to already own or be root on the path to set the ACL, a strictly stronger position
# than this defends against -- so we keep the check to the mode bits.
_dir_component_safe() {
    _st=$(stat -f '%u %Sp' "$1" 2>/dev/null) || return 1
    _owner=${_st%% *}; _mode=${_st#* }
    case " $2 " in *" $_owner "*) ;; *) return 1 ;; esac   # owned by an allowed UID?
    case "$_mode" in
        l*)                 return 1 ;;            # symlink -> writer/executor follows it elsewhere
        ?????w*|????????w*) return 1 ;;            # group- or other-writable
    esac
    return 0
}
# The root teardown helper's path must be root-owned throughout; the user's OWN repo path may
# be owned by root OR you ($uid), but never a DIFFERENT non-root user (who could redirect the
# login agent's code -> passwordless root). Same symlink + mode-bit rules for both.
dir_is_safe()     { _dir_component_safe "$1" 0; }
dir_ok_for_repo() { _dir_component_safe "$1" "0 ${uid:-$(id -u)}"; }

# Shared ancestor walk for the two install-time path guards. Emit the FIRST existing
# component of directory path $1 (walking / down to the leaf) for which the predicate
# function named in $2 returns non-zero; empty output means every existing component passed.
# Meant to run ONLY inside a command substitution: that subshell scopes the `set -f` (stop
# each segment being pathname-expanded -- a stray glob char would otherwise validate the
# wrong paths) and IFS=/ (split on separators) so the caller's shell options stay untouched.
# The predicate ($2) is a function, so it's available in this same shell.
_first_bad_ancestor() {
    set -f; IFS=/
    _acc=""
    for _seg in $1; do
        [ -n "$_seg" ] || continue          # skip the empty leading segment
        _acc="$_acc/$_seg"
        # -e follows symlinks, -L catches a dangling one; either must be vetted because the
        # writer (`install -d`, or the login agent that executes from here) follows whatever
        # the path resolves to.
        { [ -e "$_acc" ] || [ -L "$_acc" ]; } || continue
        "$2" "$_acc" || { printf '%s' "$_acc"; break; }
    done
}

# Verify EVERY existing component of path $1 (from / down to the leaf) passes predicate $2
# (a function name) -- else a non-owner could swap that component for code that runs as root
# (or as the login-agent user, who reaches root via NOPASSWD openconnect). unlink/rename is
# governed by the *parent's* write bit, so one loose/symlinked/foreign-owned ancestor is
# enough to refuse. Deriving the chain from the path (not a hardcoded pair) keeps it from
# drifting off the real install location. On failure prints "error: <offender> $3" and
# returns 1; returns 0 if all-safe.
_verify_ancestors() {
    # Fail closed on a non-absolute (or empty) path -- the walk assumes a leading /.
    case $1 in
        /*) ;;
        *)  echo "error: refusing to install under non-absolute path '$1'" >&2; return 1 ;;
    esac
    _bad=$(_first_bad_ancestor "$1" "$2")
    [ -n "$_bad" ] || return 0
    echo "error: $_bad $3" >&2
    return 1
}
# Root teardown helper: every component must be root-owned (its NOPASSWD grant can't be
# hijacked). User's repo: every component must be root- or self-owned (see dir_ok_for_repo).
verify_safe_ancestors() {
    _verify_ancestors "$1" dir_is_safe \
        "is not root-owned, is group/other-writable, or is a symlink; refusing to install a passwordless-root helper under it."
}
verify_repo_ancestors() {
    _verify_ancestors "$1" dir_ok_for_repo \
        "is group/other-writable, a symlink, or owned by another user; refusing to install. A non-owner who can alter any repo-path component plants code the login agent runs as you (-> passwordless root). Move the repo somewhere private (under your home, chmod go-w) and re-run."
}

# Recursively vet the INTERIOR of an already-ancestor-vetted repo $1: every file/dir under the
# code roots the login agent (as you) or the ROOT vpnc-script wrapper sources/execs/copies must
# be unsubvertable. root sources lib/common.sh, execs .venv/bin/python + src/dnsroute.py, and
# COPIES libexec/vpn-teardown to the root-owned NOPASSWD helper; the agent execs the bin/
# scripts + src/*.py. A group/other-writable, symlinked, or foreign-owned entry ANYWHERE under
# these is direct code-exec as you (-> passwordless root) or as root -- including a file DEEP
# under .venv/lib/.../site-packages (a .pth root's python executes), which an enumerated
# top-level list would miss. The recursive find is self-maintaining: a new src/ file or a deep
# venv path is covered automatically. Roots absent before install.sh builds .venv are skipped.
# Split out so the harness can exercise the ACCEPTED case too (which can't run the full sudo
# install path). Returns 0 if clean; prints + returns 1 on the first bad entry, OR fails CLOSED
# (refuse) if the tree could not be fully inspected.
#
# What is flagged (find is -P, so symlinks are NOT followed):
#   - a SYMLINK anywhere, EXCEPT a DIRECT child of .venv/bin (the interpreter links uv makes,
#     pointing at the system/Homebrew python; swapping one needs write on .venv/bin, whose own
#     dir mode the writable arm below catches). fnmatch `*` crosses `/`, so the exemption is
#     pinned to DIRECT children via `! -path './.venv/bin/*/*'` -- a planted .venv/bin/sub/evil
#     is NOT exempt.
#   - a FOREIGN-owned entry (! -user 0 ! -user $uid = owned by neither root nor you): a foreign
#     non-root user who could redirect the code.
#   - ANY group/other-writable entry (-perm -0020/-0002), file OR dir, EXCEPT the one known-benign
#     world-writable file uv creates (.venv/.lock, mode 0666, re-created by every `uv sync`). This
#     is FAIL-CLOSED, on purpose: an earlier round allowlisted "code" files by extension/exec-bit
#     (*.py/*.pth/*.sh + the exec bit) and so BLESSED a group/other-writable .so/.dylib (dlopen)
#     or .pyc/.pyo (bytecode) -- root-code-exec vectors a python load pulls in by CONTENT, not
#     name. Flagging EVERY writable entry (a writable DIR also lets a non-owner unlink/replace
#     what's inside) means the next unknown writable format fails CLOSED with a clear message
#     instead of being silently blessed; only the exact ./.venv/.lock is exempt so a STOCK repo
#     still installs.
#
# LIMITATION: the .venv/bin/* symlink exemption vets the link's location, not its TARGET (e.g.
# /opt/homebrew/opt/python@3.14/..., group-writable by `admin` on a multi-admin Mac). The
# interpreter target's safety is the system's Homebrew/OS posture, out of scope for this check:
# swapping it needs admin-group membership (already ~root -- admins can sudo), a strictly stronger
# position than this defends against, and vetting the target would false-positive on essentially
# every Homebrew install (mirrors the ACL LIMITATION on _dir_component_safe).
#
# Robustness (findings 2b + 6): find runs in a subshell that `cd "$_p"` FIRST and uses RELATIVE
# roots + LITERAL `./.venv/bin/*` patterns, so a glob metacharacter or space in $_p can never
# corrupt a `-path` glob (a bracket in the repo path used to flag the legit python link -> a
# fail-closed DoS). The root list holds only the roots that actually EXIST ([ -d ], word-split-
# safe via `set --`). If NO root exists, we cannot enter the repo, or find itself errors (an
# unreadable subtree), we FAIL CLOSED rather than bless a tree we could not inspect -- the old
# `find ... 2>/dev/null` made an error indistinguishable from "clean". The subshell exit status
# encodes the outcome: 0 clean, 1 offender found (its ./relative path on stdout), 2/3/4 refuse.
verify_repo_interior() {
    _p=$1
    _uid="${uid:-$(id -u)}"
    _bad=$(
        cd "$_p" 2>/dev/null || exit 3               # can't enter the repo -> fail closed
        set --                                        # build the EXISTING-root list, word-split-safe
        for _r in bin lib src libexec .venv; do
            [ -d "$_r" ] && set -- "$@" "./$_r"
        done
        [ "$#" -gt 0 ] || exit 2                       # no code roots present -> nothing vetted -> refuse
        # Capture find's OWN output+status (NOT piped to head, so its exit status survives): a
        # traversal error (unreadable subtree) must fail closed, not read as clean.
        _found=$(find "$@" \
            \( \
               \( -type l ! \( -path './.venv/bin/*' ! -path './.venv/bin/*/*' \) \) \
               -o \( ! -user 0 ! -user "$_uid" \) \
               -o \( \( -perm -0020 -o -perm -0002 \) ! -path './.venv/.lock' \) \
            \) -print 2>/dev/null) || exit 4           # find errored (unreadable subtree) -> fail closed
        [ -n "$_found" ] || exit 0                      # nothing flagged -> clean
        printf '%s\n' "$_found" | head -n1              # first offender (relative "./...")
        exit 1
    )
    _rc=$?
    [ "$_rc" = 0 ] && return 0
    if [ "$_rc" = 1 ]; then
        # $_bad is "./<rel>"; strip the leading "." and prepend $_p for an absolute report.
        echo "error: $_p${_bad#.} is group/other-writable, a symlink, or owned by another user;" >&2
        echo "       refusing to install -- the login agent or root wrapper runs code from it," >&2
        echo "       so a non-owner who can alter it gets code execution as you (passwordless" >&2
        echo "       root) or as root. chmod go-w (and fix ownership) and re-run." >&2
    else
        # 2 = no code roots, 3 = cd failed, 4 = find error / unreadable subtree: fail CLOSED.
        echo "error: could not fully verify the repo interior under $_p (missing code roots," >&2
        echo "       an unreadable subtree, or a find error) -- refusing rather than bless a tree" >&2
        echo "       it could not inspect. Check permissions/ownership under the repo and re-run." >&2
    fi
    return 1
}

# Load (or reload) the LaunchAgent, VERIFYING it actually took rather than trusting the
# loader's exit status. Bootstrapping right after booting out the old job can transiently
# fail with EIO (errno 5, "Input/output error") while that job drains -- and some launchctl
# builds print the error yet still exit 0 -- so bootout ONCE (repeating it would tear down a
# just-loaded agent on a print race), then retry `bootstrap` with a short backoff and CONFIRM
# with `launchctl print` (the same load-check do_status uses). Requires a launchctl with
# bootstrap/print (macOS 10.10+). Returns 0 once the label is confirmed loaded, else 1.
# $LAUNCHCTL / $LOAD_RETRY_SLEEP are honored only under the OC_INSTALL_TEST seam; a real
# install always uses the real launchctl.
load_agent() {
    _lc=launchctl; _slp=1
    if [ "${OC_INSTALL_TEST:-}" = 1 ]; then _lc=${LAUNCHCTL:-launchctl}; _slp=${LOAD_RETRY_SLEEP:-1}; fi
    "$_lc" bootout "gui/$uid/$label" 2>/dev/null || true    # drop any prior agent (once)
    _i=0
    while [ "$_i" -lt 5 ]; do
        "$_lc" bootstrap "gui/$uid" "$plist" 2>/dev/null || true
        "$_lc" print "gui/$uid/$label" >/dev/null 2>&1 && return 0
        _i=$((_i + 1))
        [ "$_i" -lt 5 ] && sleep "$_slp"    # backoff BETWEEN attempts, not after the last
    done
    return 1
}

do_install() {
    [ -x "$connect" ] || { echo "error: $connect not found/executable" >&2; exit 1; }
    # The LaunchAgent runs $connect as YOU on every login, and $connect reaches root via the
    # NOPASSWD openconnect rule -- so a non-owner who can write, rename, or symlink-redirect
    # ANY component the agent (as you) or the ROOT vpnc-script wrapper sources/execs gets
    # passwordless root by planting code that then runs. First verify $proj and every ancestor
    # from / down (unlink/rename is governed by the parent, so an ancestor is enough).
    verify_repo_ancestors "$proj" || exit 1
    # $proj is now vetted, so its INTERIOR only needs each component's OWN mode/owner checked (a
    # safe $proj prevents these being unlinked/replaced). Recursively walk every code root the
    # agent or root wrapper sources/execs/copies (see verify_repo_interior): a group/other-
    # writable, symlinked, or foreign-owned file ANYWHERE under them -- including deep under
    # .venv/lib -- is code-exec as you (-> passwordless root) or as root.
    verify_repo_interior "$proj" || exit 1
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
    # OC_LAUNCHD (baked into the plist) tells the connect script which recovery budget to
    # use: `keepalive` gets openconnect's short in-process reconnect (KeepAlive respawns a
    # fresh connect); `once` keeps the long budget (nothing respawns it) but still waits out
    # a slow boot network. See lib/common.sh recovery_budget.
    if [ "$keepalive" = "true" ]; then mode="keepalive"; else mode="once"; fi

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
        <string>$(xml_escape "$HOME")</string>
        <key>OC_LAUNCHD</key>
        <string>$mode</string>$_cfg_env
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
    # The rollback must NOT silently swallow a failed sudoers removal: that is the one file
    # whose survival leaves passwordless root behind. Surface it loudly (matching
    # do_uninstall's "STILL ACTIVE" warning) while still attempting the other cleanups --
    # each step is isolated so one failure can't abort the rest of the trap. The `if`
    # condition is exempt from set -e, so a failed `sudo rm` triggers the warning instead
    # of aborting mid-rollback.
    trap '
        [ "$_did_plist" = y ] && rm -f "$plist" 2>/dev/null || true
        if [ "$_did_sudoers" = y ] && ! sudo rm -f "$sudoers" 2>/dev/null; then
            echo "ERROR (rollback): could not remove $sudoers -- the passwordless-root" >&2
            echo "       sudoers rule is STILL ACTIVE. Remove it manually:" >&2
            echo "       sudo rm -f $sudoers" >&2
        fi
        [ "$_did_libexec" = y ] && sudo rm -rf "$libexecdir" 2>/dev/null || true
        rm -f "$ptmp" "${stmp:-}" 2>/dev/null || true
    ' EXIT

    echo ">> installing the root teardown helper + sudoers rule (password once)..."
    # Root-owned teardown helper -- so its NOPASSWD grant can't be hijacked by
    # editing a user-writable file. Install it BEFORE the rule that references it.
    # Only mark libexecdir for rollback if THIS run creates it. On a reinstall/upgrade the dir
    # already exists (and belongs to the working install); a rollback must not `rm -rf` it and
    # take out the live teardown helper. `[ -d ] && ... || true` keeps set -e happy.
    _pre_libexec=n; [ -d "$libexecdir" ] && _pre_libexec=y || true
    sudo install -d -o root -g wheel -m 0755 "$libexecdir"
    [ "$_pre_libexec" = y ] || _did_libexec=y   # created it -> roll it back if a later step fails
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

    rm -f "$ptmp" 2>/dev/null || true

    if ! load_agent; then
        # Files installed correctly; only the runtime load failed (usually a transient
        # EIO). KEEP them -- rolling back would drop the sudoers rule the user just entered
        # a password for -- and tell them how to finish the load.
        trap - EXIT
        echo "error: installed the files, but launchd would not load the agent after" >&2
        echo "       several tries (a transient 'Input/output error' is the usual cause)." >&2
        echo "       Finish the load, then check status:" >&2
        echo "         launchctl bootout gui/$uid/$label 2>/dev/null; launchctl bootstrap gui/$uid \"$plist\"" >&2
        echo "         ./install-autostart.sh status" >&2
        exit 1
    fi

    trap - EXIT           # success: disarm the partial-install rollback
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

# The test harness sources this file to exercise the path guards (dir_is_safe /
# verify_safe_ancestors, dir_ok_for_repo / verify_repo_ancestors) in isolation;
# OC_INSTALL_TEST=1 skips the subcommand dispatch so sourcing has no side
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
