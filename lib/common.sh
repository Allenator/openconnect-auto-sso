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

# --- recovery timing ---------------------------------------------------------------
# These four values are ONE design, so they are owned here rather than scattered:
#
# openconnect's in-process reconnect CANNOT survive a macOS sleep -- on wake its socket
# is still bound to local addresses that no longer exist, so every retry fails ("Can't
# assign requested address") until its budget expires. A FRESH openconnect connects fine.
# So when something will restart us (launchd), we give up fast and let that fresh connect
# happen. Interactively nothing would respawn us, so we keep openconnect's own long budget
# -- in-process recovery is the only recovery a terminal user has.
#
# Before connecting we wait for the server to become REACHABLE instead of exiting into
# launchd's throttle. NET_WAIT_MAX >= THROTTLE_INTERVAL is the load-bearing invariant:
# launchd's respawn delay is (THROTTLE_INTERVAL - runtime) -- it calls ThrottleInterval
# the job's "minimum runtime" -- so a job that stays alive that long always respawns
# IMMEDIATELY. Exiting earlier would just idle out the rest of the throttle window.
THROTTLE_INTERVAL=300                # plist ThrottleInterval (install-autostart.sh writes it)
NET_WAIT_MAX="$THROTTLE_INTERVAL"    # cap on the wait below; keep >= THROTTLE_INTERVAL
RECONNECT_TIMEOUT_SUPERVISED=30      # under launchd: give up fast; KeepAlive reconnects
RECONNECT_TIMEOUT_INTERACTIVE=300    # no supervisor: openconnect's own default budget

# Decide the reconnect budget + network-wait bound from whether a supervisor will restart
# us. $1 = "1" when supervised. The auto-start agent sets OC_SUPERVISED=1 in its plist;
# NOTHING else does, so a lone run (terminal, nohup, cron) is treated as unsupervised and
# keeps openconnect's long in-process budget -- because nothing would respawn it, and a
# short give-up there would kill a tunnel a >30s blip should have ridden out. We shorten
# ONLY when we know something takes over. An explicit reconnect_timeout in the config
# still wins (this only DEFAULTS it). Owned here so the connect script needs no test seam.
recovery_budget() {
    if [ "${1:-}" = 1 ]; then
        : "${RECONNECT_TIMEOUT:=$RECONNECT_TIMEOUT_SUPERVISED}"
        NET_WAIT_MAX="$THROTTLE_INTERVAL"    # wait out the throttle window (respawn is free)
    else
        : "${RECONNECT_TIMEOUT:=$RECONNECT_TIMEOUT_INTERACTIVE}"
        NET_WAIT_MAX=10                       # a human is watching; fail fast, don't hang
    fi
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
