# common.sh -- constants shared across privilege domains. Sourced (never executed)
# by bin/openconnect-auto-sso (user) and bin/vpnc-slice (root), which otherwise
# communicate only through argv and files.

# First line of every /etc/resolver file we write. The wrapper writes it; the
# connect script's startup sweep recognizes our leftovers by it (whole-line
# match). Writer and sweeper MUST agree, so it is defined only here.
RESOLVER_MARKER='# openconnect-auto-sso'

# Where install-autostart.sh installs the root-owned teardown helper, and where the
# connect script + installer reference it. Single owner so the connect script's
# invocation, the installer's copy, and the sudoers rule can't drift apart.
LIBEXEC_DIR='/usr/local/libexec/openconnect-auto-sso'
TEARDOWN_BIN="$LIBEXEC_DIR/vpn-teardown"
