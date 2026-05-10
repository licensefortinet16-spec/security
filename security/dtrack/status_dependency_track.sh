#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SECURITY_ROOT:-/opt/security}"
cd "$ROOT_DIR/dtrack"

docker compose ps
echo
echo "API health:"
curl -fsS http://192.168.1.22:8081/api/version || true
echo
echo "Local access:"
echo "  Frontend: http://192.168.1.22:8080"
echo "  API:      http://192.168.1.22:8081"
echo
echo "Remote workstation access via SSH tunnel:"
echo "  ssh -L 8080:127.0.0.1:8080 -L 8081:127.0.0.1:8081 root@192.168.1.22"
