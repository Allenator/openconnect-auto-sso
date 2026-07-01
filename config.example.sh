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
