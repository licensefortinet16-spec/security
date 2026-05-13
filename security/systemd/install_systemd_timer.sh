#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root on the central server"
  exit 2
fi

install -o root -g root -m 0644 /opt/security/security/systemd/container-security-scan.service /etc/systemd/system/container-security-scan.service
install -o root -g root -m 0644 /opt/security/security/systemd/container-security-scan.timer /etc/systemd/system/container-security-scan.timer
systemctl daemon-reload
systemctl enable --now container-security-scan.timer
systemctl list-timers --all --no-pager | grep container-security || true
