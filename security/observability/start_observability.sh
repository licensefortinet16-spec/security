#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SECURITY_ROOT:-/opt/security}"
cd "$ROOT_DIR/observability"

docker compose up -d
docker compose ps
