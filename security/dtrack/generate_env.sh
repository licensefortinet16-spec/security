#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SECURITY_ROOT:-/opt/security}"
ENV_FILE="$ROOT_DIR/dtrack/.env"

if [ -f "$ENV_FILE" ]; then
  echo "$ENV_FILE already exists; refusing to overwrite"
  exit 0
fi

password="$(openssl rand -base64 36 | tr -d '\n')"
umask 077
printf 'POSTGRES_PASSWORD=%s\n' "$password" > "$ENV_FILE"
chmod 600 "$ENV_FILE"
echo "created $ENV_FILE with mode 600"
