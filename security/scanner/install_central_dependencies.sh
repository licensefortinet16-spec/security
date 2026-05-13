#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root on the central server"
  exit 2
fi

if [ -r /etc/os-release ]; then
  . /etc/os-release
else
  echo "/etc/os-release not found"
  exit 2
fi

if [ "${ID:-}" != "debian" ]; then
  echo "unsupported distribution: ${ID:-unknown}"
  exit 2
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates \
  curl \
  docker-compose \
  docker.io \
  git \
  gnupg \
  jq \
  lsb-release \
  openssl \
  python3-pip

curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key -o /tmp/trivy-public.key
gpg --dearmor -o /usr/share/keyrings/trivy.gpg /tmp/trivy-public.key
chmod 644 /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y trivy

systemctl enable --now docker

trivy --version
docker --version
docker compose version
