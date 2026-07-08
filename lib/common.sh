# common.sh -- constants shared across privilege domains. Sourced (never executed)
# by bin/openconnect-auto-sso (user) and bin/vpnc-slice (root), which otherwise
# communicate only through argv and files.

# First line of every /etc/resolver file we write. The wrapper writes it; the
# connect script's startup sweep recognizes our leftovers by it (whole-line
# match). Writer and sweeper MUST agree, so it is defined only here.
RESOLVER_MARKER='# openconnect-auto-sso'

# Root-owned file holding the running openconnect's PID (its VPNPID, recorded by
# the wrapper on connect). The privileged vpn-teardown helper reads it to stop the
# tunnel cleanly on logout/uninstall. NOTE: libexec/vpn-teardown hardcodes this
# same literal -- it must NOT source this (user-writable) file while running as
# root -- so keep the two in sync.
VPNPID_FILE='/var/run/openconnect-auto-sso.vpnpid'
