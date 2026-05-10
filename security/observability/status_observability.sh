#!/usr/bin/env bash
set -euo pipefail

echo "Prometheus:"
curl -fsS http://127.0.0.1:9090/-/ready || true
echo
echo "Grafana:"
curl -fsS http://127.0.0.1:3000/api/health || true
echo
echo "Dashboards:"
curl -fsS http://127.0.0.1:3000/api/search?query=Container%20Security || true
