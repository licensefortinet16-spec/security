#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root on the central server"
  exit 2
fi

install -o root -g root -m 0644 /opt/security/systemd/container-security-status.service /etc/systemd/system/container-security-status.service
systemctl daemon-reload
systemctl enable --now container-security-status.service
systemctl status container-security-status.service --no-pager --lines=20
