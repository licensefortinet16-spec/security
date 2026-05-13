#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SECURITY_ROOT:-/opt/security/security}"
ENV_FILE="$ROOT_DIR/config/dependency-track.env"
PUBLIC_HOST="${PUBLIC_HOST:-200.160.19.14}"

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <dependency-track-api-key>"
  exit 2
fi

api_key="$1"
if [ -z "$api_key" ]; then
  echo "api key cannot be empty"
  exit 2
fi

umask 077
cat > "$ENV_FILE" <<EOF
DTRACK_URL=http://${PUBLIC_HOST}:8081
DTRACK_API_KEY=$api_key
EOF

chmod 600 "$ENV_FILE"
echo "configured $ENV_FILE with mode 600"
