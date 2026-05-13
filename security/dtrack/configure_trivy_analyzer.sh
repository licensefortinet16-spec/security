#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SECURITY_ROOT:-/opt/security/security}"
TRIVY_BASE_URL="${TRIVY_BASE_URL:-http://trivy:8082}"

cd "$ROOT_DIR/dtrack"

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

TRIVY_API_TOKEN="${TRIVY_API_TOKEN:-}"
if [ -z "$TRIVY_API_TOKEN" ]; then
  echo "TRIVY_API_TOKEN is not set; run ./generate_env.sh or set it in $ROOT_DIR/dtrack/.env"
  exit 2
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

secret_key_file="$tmp_dir/secret.key"
plain_token_file="$tmp_dir/trivy.token"
encrypted_payload_file="$tmp_dir/trivy.payload"

docker compose exec -T dtrack-apiserver cat /data/.dependency-track/keys/secret.key > "$secret_key_file"
printf '%s' "$TRIVY_API_TOKEN" > "$plain_token_file"

secret_key_hex="$(python3 - "$secret_key_file" <<'PY'
import pathlib
import sys

print(pathlib.Path(sys.argv[1]).read_bytes().hex())
PY
)"

iv_hex="$(openssl rand -hex 16)"
openssl enc -aes-256-cbc -K "$secret_key_hex" -iv "$iv_hex" -nosalt -in "$plain_token_file" -out "$tmp_dir/trivy.token.enc"

python3 - "$iv_hex" "$tmp_dir/trivy.token.enc" "$encrypted_payload_file" <<'PY'
import binascii
import pathlib
import sys

iv_hex, encrypted_path, output_path = sys.argv[1:]
payload = binascii.unhexlify(iv_hex) + pathlib.Path(encrypted_path).read_bytes()
pathlib.Path(output_path).write_bytes(payload)
PY

encrypted_token="$(base64 -w0 < "$encrypted_payload_file")"

sql=$(cat <<SQL
update "CONFIGPROPERTY"
set "PROPERTYVALUE" = 'true'
where "GROUPNAME" = 'scanner' and "PROPERTYNAME" = 'trivy.enabled';

update "CONFIGPROPERTY"
set "PROPERTYVALUE" = '${TRIVY_BASE_URL}'
where "GROUPNAME" = 'scanner' and "PROPERTYNAME" = 'trivy.base.url';

update "CONFIGPROPERTY"
set "PROPERTYVALUE" = '${encrypted_token}'
where "GROUPNAME" = 'scanner' and "PROPERTYNAME" = 'trivy.api.token';

update "CONFIGPROPERTY"
set "PROPERTYVALUE" = 'false'
where "GROUPNAME" = 'scanner' and "PROPERTYNAME" = 'ossindex.enabled';
SQL
)

printf '%s\n' "$sql" | docker compose exec -T postgres psql -U dtrack -d dtrack
docker compose restart dtrack-apiserver
echo "configured Dependency-Track Trivy analyzer: enabled=true base.url=$TRIVY_BASE_URL"
