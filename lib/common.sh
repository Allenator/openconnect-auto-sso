# common.sh -- constants and helpers shared across privilege domains. Sourced (never
# executed) by bin/openconnect-auto-sso (user), bin/vpnc-slice (root), and
# install-autostart.sh, which otherwise communicate only through argv and files.
# Everything here must be side-effect-free at source time. (libexec/vpn-teardown
# deliberately does NOT source this -- a root helper must not read a user-writable file.)

# First line of every /etc/resolver file we write. The wrapper writes it; the
# connect script's startup sweep recognizes our leftovers by it (whole-line
# match). Writer and sweeper MUST agree, so it is defined only here.
RESOLVER_MARKER='# openconnect-auto-sso'

# Where install-autostart.sh installs the root-owned teardown helper, and where the
# connect script + installer reference it. Single owner so the connect script's
# invocation, the installer's copy, and the sudoers rule can't drift apart.
LIBEXEC_DIR='/usr/local/libexec/openconnect-auto-sso'
TEARDOWN_BIN="$LIBEXEC_DIR/vpn-teardown"

# True if process $1's FULL argv (ps -o command=) contains the fixed string $2. The single place
# the "is this PID still really ours?" check lives, so the connect script's backstop + _end_browser
# and vpnc-slice's _is_dnsroute can't drift. Used to RE-CONFIRM a PID right before signaling it: a
# bg child's PID is freed the moment it's reaped, so a raw kill could hit a reused PID -- matching
# the full argv first makes that (almost) impossible. `grep -qF`: $2 is a literal (a path, which may
# hold regex metacharacters), never an ERE. Empty/absent PID -> not ours.
#
# This is a BOOLEAN predicate: it returns non-zero on a no-match or an empty PID, which WOULD trip a
# bare-statement caller's `set -e` exactly as any other failing command does. It is safe ONLY
# because every caller uses it in a condition context (if / && / ||), never as a bare statement --
# an earlier comment wrongly claimed the if/return wrapper made it errexit-proof "whatever the call
# context"; it does not, so the equivalent one-liner below replaces it.
#
# RESIDUAL (finding 12, DEFERRED): $2 is PER-REPO (a repo path), not per-RUN, so a PID reused onto a
# CONCURRENT same-repo run's live process could still pass this confirm. Very narrow (needs PID
# reuse landing on a live same-repo process); the connect script's _oc_pid clear (finding 4) shut
# the biggest window. A per-run token is left to a future round.
pid_argv_has() {
    [ -n "${1:-}" ] && ps -p "$1" -o command= 2>/dev/null | grep -qF -- "$2"
}

# --- recovery timing ---------------------------------------------------------------
# These values are ONE design, so they are owned here rather than scattered. They serve
# TWO INDEPENDENT concerns, and OC_LAUNCHD ("keepalive" | "once" | unset) drives BOTH:
#
# (1) Respawn budget -> RECONNECT_TIMEOUT. openconnect's in-process reconnect CANNOT
# survive a macOS sleep -- on wake its socket is still bound to local addresses that no
# longer exist, so every retry fails ("Can't assign requested address") until the budget
# expires. A FRESH openconnect connects fine. So we give up FAST (30s) and let a fresh
# connect happen ONLY when something will respawn us -- that is `keepalive` (launchd's
# KeepAlive restarts the connect script on exit). With `--once` (KeepAlive=false) and
# interactively NOTHING respawns us, so we KEEP openconnect's own long budget (300s): a
# short give-up there would kill a tunnel that a >30s blip should have ridden out, with no
# restart to recover it. The deciding bit here is "will I be respawned", NOT "am I at login".
#
# (2) Boot network-wait -> NET_WAIT_MAX. Before connecting we wait for the server to become
# REACHABLE instead of exiting into launchd's throttle. BOTH at-login modes (`once` AND
# `keepalive`) get the long wait (THROTTLE_INTERVAL): a login run may start before Wi-Fi is
# up and should wait it out rather than fail. That is why `once` gets the long wait yet
# keeps the long reconnect budget above -- the two concerns are decided SEPARATELY. For
# `keepalive`, NET_WAIT_MAX >= THROTTLE_INTERVAL is additionally load-bearing: launchd's
# respawn delay is (THROTTLE_INTERVAL - runtime) -- it calls ThrottleInterval the job's
# "minimum runtime" -- so a job that stays alive that long always respawns IMMEDIATELY;
# exiting earlier would just idle out the rest of the window. Interactively (unset) a human
# is watching, so we fail the wait fast (10s) and never hang.
THROTTLE_INTERVAL=300                # plist ThrottleInterval (install-autostart.sh writes it)
NET_WAIT_MAX="$THROTTLE_INTERVAL"    # cap on the wait below; keep >= THROTTLE_INTERVAL
RECONNECT_TIMEOUT_SUPERVISED=30      # keepalive respawns us: give up fast, take a fresh connect
RECONNECT_TIMEOUT_INTERACTIVE=300    # nothing respawns us (--once / terminal): openconnect's default

# Decide the reconnect budget + network-wait bound from OC_LAUNCHD, passed as $1:
#   keepalive -> respawned:                short give-up (30),  long wait (300).
#   once      -> at login but NOT respawned: LONG give-up (300), long wait (300).
#   unset     -> interactive:               long give-up (300),  short wait (10).
# The auto-start agent sets OC_LAUNCHD in its plist (`keepalive` or `once`); NOTHING else
# does, so a lone run (terminal, nohup, cron) reads as unset. An explicit reconnect_timeout
# in the config still wins (this only DEFAULTS it). Owned here so the connect script needs
# no test seam.
recovery_budget() {
    case "${1:-}" in
        keepalive)                                       # launchd's KeepAlive respawns us
            : "${RECONNECT_TIMEOUT:=$RECONNECT_TIMEOUT_SUPERVISED}"
            NET_WAIT_MAX="$THROTTLE_INTERVAL"            # wait out the throttle window (respawn is free)
            ;;
        once)                                            # runs at login, but NO respawner
            : "${RECONNECT_TIMEOUT:=$RECONNECT_TIMEOUT_INTERACTIVE}"  # keep the long budget
            NET_WAIT_MAX="$THROTTLE_INTERVAL"            # boot Wi-Fi may be slow; wait it out
            ;;
        *)                                               # interactive / unsupervised
            : "${RECONNECT_TIMEOUT:=$RECONNECT_TIMEOUT_INTERACTIVE}"
            NET_WAIT_MAX=10                              # a human is watching; fail fast, don't hang
            ;;
    esac
}

# Split openconnect's server form -- [https://]host[:port][/group] -- into
# $HOSTPORT_HOST / $HOSTPORT_PORT. Pure parameter expansion: no eval, no subshell.
server_hostport() {
    _hp=${1#*://}                    # strip scheme (no-op when absent)
    _hp=${_hp%%/*}                   # strip trailing path / usergroup
    _hp=${_hp##*@}                   # strip userinfo (last @: @ can't appear in the host)
    case $_hp in
        \[*\]:*) HOSTPORT_HOST=${_hp%%\]*}; HOSTPORT_HOST=${HOSTPORT_HOST#\[}
                 HOSTPORT_PORT=${_hp##*\]:} ;;                        # [v6]:port
        \[*\])   HOSTPORT_HOST=${_hp#\[}; HOSTPORT_HOST=${HOSTPORT_HOST%\]}
                 HOSTPORT_PORT=443 ;;                                 # [v6]
        *:*:*)   HOSTPORT_HOST=$_hp; HOSTPORT_PORT=443 ;;             # bare v6 literal
        *:*)     HOSTPORT_HOST=${_hp%:*}; HOSTPORT_PORT=${_hp#*:} ;;  # host:port
        *)       HOSTPORT_HOST=$_hp; HOSTPORT_PORT=443 ;;
    esac
}

# True if a TCP connection to $1:$2 succeeds. `-G` is Apple's CONNECT timeout and is
# load-bearing: `-w` alone is only an IDLE timeout, so an unreachable host would stall
# the probe ~75s (the kernel's connect timeout) instead of failing in seconds. Absolute
# path so a Homebrew GNU netcat (which has no -G) can't shadow it. NC_BIN is overridable
# only so tests can stub the probe -- the connect script calls this as the user, and
# root's vpnc-slice never calls it at all.
NC_BIN="${NC_BIN:-/usr/bin/nc}"
server_reachable() {
    "$NC_BIN" -z -G 3 -w 3 "$1" "$2" >/dev/null 2>&1
}

# Wait (bounded by NET_WAIT_MAX) until the VPN server accepts TCP, so we never try to
# authenticate into a network that isn't up yet. Returns 0 once reachable, 1 on timeout.
#
# We probe REACHABILITY rather than "is there a default route": a default route can be
# perfectly present while the VPN is unreachable (the AP is up but the WAN is down, a modem
# reboot), and a route check cannot see DNS readiness either. This covers both, works over
# IPv4 or IPv6, and needs no `route` binary.
#
# CAVEAT: a captive portal that DNATs the VPN port makes the handshake succeed, so this can
# report "reachable" while the real server isn't there. It is a readiness gate, not a
# guarantee -- Phase 1 still reports the real error in that case.
wait_for_server() {
    server_hostport "$1"
    # SKIP the gate (proceed, don't stall) when we can't run a meaningful probe -- a
    # broken probe must not silently burn the whole NET_WAIT_MAX on every connect. Cases:
    # the probe tool is missing/non-executable, or a malformed `server` yielded no host or
    # a non-numeric port. Phase 1 then reports the real error instead of a 5-minute hang.
    [ -x "$NC_BIN" ] || return 0
    [ -n "$HOSTPORT_HOST" ] || return 0
    case $HOSTPORT_PORT in ''|*[!0-9]*) return 0 ;; esac
    # Fail safe if `date` is unavailable rather than looping forever on a bad comparison.
    _deadline=$(date +%s) || return 0
    _deadline=$(( _deadline + NET_WAIT_MAX ))
    _announced=n
    while ! server_reachable "$HOSTPORT_HOST" "$HOSTPORT_PORT"; do
        _now=$(date +%s) || return 0
        if [ "$_now" -ge "$_deadline" ]; then
            echo "WARNING: $HOSTPORT_HOST:$HOSTPORT_PORT still unreachable after" \
                 "${NET_WAIT_MAX}s; trying anyway." >&2
            return 1
        fi
        if [ "$_announced" = n ]; then
            echo ">> waiting for $HOSTPORT_HOST:$HOSTPORT_PORT to become reachable..." >&2
            _announced=y
        fi
        sleep 2
    done
    if [ "$_announced" = y ]; then
        echo ">> $HOSTPORT_HOST:$HOSTPORT_PORT is reachable; continuing." >&2
    fi
    return 0
}
