#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${SECURITY_ROOT:-/opt/security}"
BACKUP_DIR="$ROOT_DIR/output/backups/dependency-track"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/dtrack_postgres_$STAMP.sql.gz"

mkdir -p "$BACKUP_DIR"
chmod 750 "$ROOT_DIR/output/backups" "$BACKUP_DIR" 2>/dev/null || true

if ! docker ps --format '{{.Names}}' | grep -qx 'dtrack-postgres'; then
  echo "dtrack-postgres container is not running"
  exit 2
fi

docker exec dtrack-postgres pg_dump -U dtrack -d dtrack | gzip -9 > "$OUT"
chmod 640 "$OUT"
echo "$OUT"
