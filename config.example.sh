# openconnect-auto-sso configuration.
# Copy this file to config.sh and edit. config.sh is gitignored — keep your
# real server and routes out of version control.

# VPN server: hostname or full URL. Required.
SERVER="vpn.example.com"

# openconnect protocol. Blank lets openconnect auto-detect.
# Set explicitly only if needed, e.g. anyconnect / gp / pulse / fortinet.
PROTOCOL=""

# Split-tunnel routes, passed to vpn-slice. Blank = full tunnel (default vpnc-script).
# Space-separated hosts/CIDRs; prefix a CIDR with % to EXCLUDE it from the tunnel.
# Example (also keeps Tailscale's CGNAT range off the VPN):
#   SPLIT_ROUTES="10.0.0.0/8 vpn-host.example.com %100.64.0.0/10"
SPLIT_ROUTES=""

# Persistent browser-profile name (Qt on-disk storage key). Usually leave as-is.
PROFILE_NAME="openconnect-auto-sso"

# openconnect's external-browser loopback callback (host:port). Rarely changed.
CALLBACK="localhost:29786"

# Keepalive (optional): some servers drop an idle tunnel. If set, ping this host
# through the tunnel every KEEPALIVE_INTERVAL seconds to keep it alive. The host
# MUST be reachable inside the VPN (within SPLIT_ROUTES, or any host in full-tunnel
# mode) so the traffic actually goes through the tunnel. Blank = disabled.
KEEPALIVE_HOST=""
KEEPALIVE_INTERVAL="30"

# vpn-slice blocks incoming connections from the VPN by default, via a pf firewall
# rule that also disables iCloud Private Relay. Set to 1 to allow incoming (pass
# vpn-slice -i): no pf rule, so Private Relay keeps working -- at the cost of hosts
# on the VPN being able to reach open ports on your machine. Only affects split mode.
ALLOW_INCOMING="0"

# Split DNS: comma-separated domains resolved via the VPN's DNS servers (pushed
# dynamically by the connection), like Tailscale's MagicDNS for *.ts.net -- queries
# for these go to the VPN DNS, everything else keeps your normal resolver.
# e.g. VPN_DOMAINS="yale.edu"
VPN_DOMAINS=""

# Consume routes the VPN pushes instead of hardcoding them:
#   ROUTE_INTERNAL=1  also route the VPN's own subnet (server-provided)
#   ROUTE_SPLITS=1    also route the server's split-include subnets (if it sends any)
ROUTE_INTERNAL="0"
ROUTE_SPLITS="0"
