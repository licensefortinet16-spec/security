#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SECURITY_ROOT:-/opt/security/security}"
PUBLIC_HOST="${PUBLIC_HOST:-200.160.19.14}"
cd "$ROOT_DIR/dtrack"

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

docker compose ps
echo
echo "API health:"
curl -fsS "http://${PUBLIC_HOST}:8081/api/version" || true
echo
echo "Local access:"
echo "  Frontend: http://${PUBLIC_HOST}:8080"
echo "  API:      http://${PUBLIC_HOST}:8081"
echo
echo "Remote workstation access via SSH tunnel:"
echo "  ssh -L 8080:${PUBLIC_HOST}:8080 -L 8081:${PUBLIC_HOST}:8081 root@${PUBLIC_HOST}"
