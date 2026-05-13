#!/usr/bin/env bash
set -euo pipefail

ALLOWED_IPS="${ALLOWED_IPS:-200.160.19.2,200.160.19.14,200.160.19.1,172.30.32.67,200.160.16.18}"
WEB_PORTS="${WEB_PORTS:-8080,8081,8090}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root on the central server"
  exit 2
fi

if ! command -v nft >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y nftables
fi

mkdir -p /etc/nftables.d
allowed_ips_set="$(printf '%s' "$ALLOWED_IPS" | tr ',' '\n' | awk 'NF {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0); printf "%s%s", sep, $0; sep=", "}')"
if [ -z "$allowed_ips_set" ]; then
  echo "ALLOWED_IPS cannot be empty"
  exit 2
fi

cat >/etc/nftables.d/container-security-monitor.nft <<EOF
table inet container_security_monitor {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport { $WEB_PORTS } ip saddr != { $allowed_ips_set } drop
  }
}
EOF

if ! grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null; then
  printf '%s\n' 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
fi

nft delete table inet container_security_monitor 2>/dev/null || true
nft -f /etc/nftables.d/container-security-monitor.nft
systemctl enable --now nftables
nft list table inet container_security_monitor
