#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root on the central server"
  exit 2
fi

install -o root -g root -m 0750 -d /etc/container-security-monitor
if [ ! -f /etc/container-security-monitor/status-password ]; then
  openssl rand -base64 36 | tr -d '\n' > /etc/container-security-monitor/status-password
  printf '\n' >> /etc/container-security-monitor/status-password
  chown root:root /etc/container-security-monitor/status-password
  chmod 0600 /etc/container-security-monitor/status-password
fi
if [ ! -f /etc/container-security-monitor/status-session.secret ]; then
  openssl rand -hex 32 > /etc/container-security-monitor/status-session.secret
  chown root:root /etc/container-security-monitor/status-session.secret
  chmod 0600 /etc/container-security-monitor/status-session.secret
fi
if [ ! -f /etc/container-security-monitor/status.env ]; then
  {
    printf 'SECURITY_STATUS_USERNAME=%s\n' admin
    printf 'SECURITY_STATUS_PASSWORD_FILE=%s\n' /etc/container-security-monitor/status-password
    printf 'SECURITY_STATUS_SESSION_FILE=%s\n' /etc/container-security-monitor/status-session.secret
  } > /etc/container-security-monitor/status.env
  chown root:root /etc/container-security-monitor/status.env
  chmod 0600 /etc/container-security-monitor/status.env
  echo "created /etc/container-security-monitor/status.env with user admin and a generated password"
fi

install -o root -g root -m 0644 /opt/security/security/systemd/container-security-status.service /etc/systemd/system/container-security-status.service
systemctl daemon-reload
systemctl enable --now container-security-status.service
systemctl status container-security-status.service --no-pager --lines=20
