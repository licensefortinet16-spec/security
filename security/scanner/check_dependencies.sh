#!/usr/bin/env bash
set -u

ROOT_DIR="${SECURITY_ROOT:-/opt/security/security}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
LOG_DIR="$ROOT_DIR/output/logs"
LOG_FILE="$LOG_DIR/dependencies_$RUN_ID.log"

mkdir -p "$LOG_DIR"

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE"
}

status=0

require() {
  name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    log "OK required dependency found: $name=$(command -v "$name")"
  else
    log "ERROR required dependency missing: $name"
    status=2
  fi
}

optional() {
  name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    log "OK optional dependency found: $name=$(command -v "$name")"
  else
    log "WARN optional dependency missing: $name"
    if [ "$status" -eq 0 ]; then
      status=1
    fi
  fi
}

log "dependency validation started root=$ROOT_DIR run_id=$RUN_ID"

require bash
require ssh
require python3

optional trivy
optional curl
optional jq
optional git

if command -v trivy >/dev/null 2>&1; then
  log "trivy_version=$(trivy --version | head -1)"
else
  log "trivy_status=missing central_only_scans_disabled"
fi

log "dependency validation finished status=$status"
exit "$status"
