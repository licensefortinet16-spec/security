#!/usr/bin/env bash
set -euo pipefail

LAN_CIDR="${LAN_CIDR:-192.168.1.0/24}"
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
cat >/etc/nftables.d/container-security-monitor.nft <<EOF
table inet container_security_monitor {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport { $WEB_PORTS } ip saddr != $LAN_CIDR drop
  }
}
EOF

if ! grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null; then
  printf '%s\n' 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
fi

nft -f /etc/nftables.d/container-security-monitor.nft
systemctl enable --now nftables
nft list table inet container_security_monitor
