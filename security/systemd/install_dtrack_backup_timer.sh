#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root on the central server"
  exit 2
fi

install -o root -g root -m 0644 /opt/security/systemd/container-security-dtrack-backup.service /etc/systemd/system/container-security-dtrack-backup.service
install -o root -g root -m 0644 /opt/security/systemd/container-security-dtrack-backup.timer /etc/systemd/system/container-security-dtrack-backup.timer
systemctl daemon-reload
systemctl enable --now container-security-dtrack-backup.timer
systemctl list-timers --all --no-pager | grep container-security-dtrack-backup || true
