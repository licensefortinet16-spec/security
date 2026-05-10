#!/usr/bin/env bash
set -u

ROOT_DIR="${SECURITY_ROOT:-/opt/security}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
LOG_DIR="$ROOT_DIR/output/logs"
LOG_FILE="$LOG_DIR/scan_$RUN_ID.log"

mkdir -p "$LOG_DIR"

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE"
}

log "scan started root=$ROOT_DIR run_id=$RUN_ID"

dep_status=0
"$ROOT_DIR/scanner/check_dependencies.sh"
dep_status=$?
if [ "$dep_status" -eq 2 ]; then
  log "scan failed: required dependencies missing"
  exit 2
fi

inventory_status=0
python3 "$ROOT_DIR/collectors/docker_inventory.py" \
  --root "$ROOT_DIR" \
  --run-id "$RUN_ID"
inventory_status=$?

image_sync_status=0
if command -v docker >/dev/null 2>&1; then
  python3 "$ROOT_DIR/scanner/sync_images_from_targets.py" \
    --root "$ROOT_DIR" \
    --run-id "$RUN_ID"
  image_sync_status=$?
else
  log "docker not installed on central server; skipping image sync"
  image_sync_status=1
fi

trivy_status=0
if command -v trivy >/dev/null 2>&1; then
  python3 "$ROOT_DIR/scanner/trivy_central_scan.py" \
    --root "$ROOT_DIR" \
    --run-id "$RUN_ID"
  trivy_status=$?
else
  log "trivy not installed on central server; skipping central image scans for run_id=$RUN_ID"
  trivy_status=1
fi

dtrack_status=0
python3 "$ROOT_DIR/dtrack/upload_sboms.py" \
  --root "$ROOT_DIR" \
  --run-id "$RUN_ID"
dtrack_status=$?

dtrack_analysis_status=0
python3 "$ROOT_DIR/dtrack/check_analysis.py" \
  --root "$ROOT_DIR" \
  --run-id "$RUN_ID" \
  --poll-seconds "${DTRACK_ANALYSIS_POLL_SECONDS:-120}" \
  --poll-interval "${DTRACK_ANALYSIS_POLL_INTERVAL:-15}"
dtrack_analysis_status=$?

report_status=0
python3 "$ROOT_DIR/reports/generate_reports.py" \
  --root "$ROOT_DIR" \
  --run-id "$RUN_ID"
report_status=$?

alerts_status=0
python3 "$ROOT_DIR/integrations/evaluate_alerts.py" \
  --root "$ROOT_DIR" \
  --run-id "$RUN_ID"
alerts_status=$?

metrics_status=0
python3 "$ROOT_DIR/integrations/export_metrics.py" \
  --root "$ROOT_DIR" \
  --run-id "$RUN_ID"
metrics_status=$?

cleanup_status=0
python3 "$ROOT_DIR/scanner/cleanup_retention.py" \
  --root "$ROOT_DIR"
cleanup_status=$?

final_status=0
if [ "$inventory_status" -eq 2 ]; then
  final_status=2
elif [ "$inventory_status" -ne 0 ] || [ "$image_sync_status" -ne 0 ] || [ "$trivy_status" -ne 0 ] || [ "$dtrack_status" -ne 0 ] || [ "$dtrack_analysis_status" -ne 0 ] || [ "$dep_status" -ne 0 ] || [ "$report_status" -ne 0 ] || [ "$alerts_status" -ne 0 ] || [ "$metrics_status" -ne 0 ] || [ "$cleanup_status" -ne 0 ]; then
  final_status=1
fi

case "$final_status" in
  0) log "scan finished status=success" ;;
  1) log "scan finished status=partial_success" ;;
  *) log "scan finished status=failed" ;;
esac

exit "$final_status"
