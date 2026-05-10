#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SECURITY_ROOT:-/opt/security}"
cd "$ROOT_DIR/dtrack"

if [ ! -f .env ]; then
  ./generate_env.sh
fi

docker compose pull
docker compose up -d
docker compose ps
