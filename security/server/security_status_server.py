#!/usr/bin/env python3
import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(os.environ.get("SECURITY_ROOT", "/opt/security"))
BIND = os.environ.get("SECURITY_STATUS_BIND", "192.168.1.22")
PORT = int(os.environ.get("SECURITY_STATUS_PORT", "8090"))


def read_json(path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def esc(value):
    return html.escape(str(value if value is not None else ""))


def latest_file(directory, pattern):
    files = sorted(directory.glob(pattern))
    return files[-1] if files else None


class Handler(BaseHTTPRequestHandler):
    server_version = "ContainerSecurityStatus/0.1"

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.html(render_index())
        elif path == "/health":
            self.json({"status": "ok"})
        elif path == "/api/status":
            self.json(status_payload())
        elif path == "/metrics":
            self.file(ROOT / "output" / "metrics" / "container_security_latest.prom", "text/plain; charset=utf-8")
        elif path == "/reports/executive":
            self.file(ROOT / "output" / "reports" / "executive_report_latest.html", "text/html; charset=utf-8")
        elif path == "/reports/technical":
            self.file(ROOT / "output" / "reports" / "technical_report_latest.html", "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def html(self, content, status=200):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def json(self, payload, status=200):
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def file(self, path, content_type):
        if not path.exists():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


def status_payload():
    risk = read_json(ROOT / "output" / "history" / "risk_scores_latest.json", {})
    inventory_path = latest_file(ROOT / "output" / "inventory", "inventory_*.json")
    inventory = read_json(inventory_path, {}) if inventory_path else {}
    metrics_path = latest_file(ROOT / "output" / "metrics", "metrics_summary_*.json")
    metrics = read_json(metrics_path, {}) if metrics_path else {}
    dtrack_path = latest_file(ROOT / "output" / "dtrack", "dtrack_upload_*.json")
    dtrack = read_json(dtrack_path, {}) if dtrack_path else {}
    dtrack_analysis_path = latest_file(ROOT / "output" / "dtrack", "dtrack_analysis_*.json")
    dtrack_analysis = read_json(dtrack_analysis_path, {}) if dtrack_analysis_path else {}
    trivy_path = latest_file(ROOT / "output" / "trivy", "trivy_summary_*.json")
    trivy = read_json(trivy_path, {}) if trivy_path else {}
    alerts_path = latest_file(ROOT / "output" / "alerts", "alerts_*.json")
    alerts = read_json(alerts_path, {}) if alerts_path else {}

    scores = risk.get("scores", [])
    return {
        "run_id": risk.get("run_id") or inventory.get("run_id"),
        "inventory_status": inventory.get("status"),
        "summary": inventory.get("summary", {}),
        "vulnerability_summary": risk.get("vulnerability_summary", {}),
        "context_summary": risk.get("context_summary", []),
        "trivy": {
            "images_total": trivy.get("images_total"),
            "success": trivy.get("success"),
            "failed": trivy.get("failed"),
        },
        "dependency_track": {
            "status": dtrack.get("status"),
            "configured": dtrack.get("configured"),
            "uploaded": dtrack.get("uploaded"),
            "failed": dtrack.get("failed"),
            "analysis_status": dtrack_analysis.get("status"),
            "analysis_totals": dtrack_analysis.get("totals", {}),
            "source_note": dtrack_analysis.get("source_note"),
        },
        "alerts": {
            "status": alerts.get("status"),
            "totals": alerts.get("totals", {}),
            "active_rules": alerts.get("alerts", []),
        },
        "metrics": metrics,
        "top_risks": compact_scores(scores[:10]),
    }


def compact_scores(scores):
    rows = []
    for item in scores:
        rows.append({
            "score": item.get("score"),
            "classification": item.get("classification"),
            "context": item.get("context"),
            "host_name": item.get("host_name"),
            "container_name": item.get("container_name"),
            "image": item.get("image"),
            "findings": item.get("findings"),
        })
    return rows


def render_index():
    status = status_payload()
    summary = status.get("summary") or {}
    vulns = status.get("vulnerability_summary") or {}
    top_rows = []
    for item in status.get("top_risks", []):
        top_rows.append(
            "<tr>"
            f"<td>{esc(item.get('score'))}</td>"
            f"<td>{esc(item.get('classification'))}</td>"
            f"<td>{esc(item.get('context'))}</td>"
            f"<td>{esc(item.get('host_name'))}</td>"
            f"<td>{esc(item.get('container_name'))}</td>"
            f"<td>{esc(item.get('image'))}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Container Security Monitor</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2933; }}
    h1, h2 {{ color: #102a43; }}
    a {{ color: #0b5cad; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0 28px; }}
    th, td {{ border: 1px solid #bcccdc; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f0f4f8; }}
  </style>
</head>
<body>
  <h1>Container Security Monitor</h1>
  <p><strong>Run ID:</strong> {esc(status.get('run_id'))}<br>
  <strong>Status inventario:</strong> {esc(status.get('inventory_status'))}<br>
  <strong>Dependency-Track:</strong> {esc((status.get('dependency_track') or {}).get('status'))}<br>
  <strong>Correlacao DT:</strong> {esc((status.get('dependency_track') or {}).get('analysis_status'))}<br>
  <strong>Alertas:</strong> {esc((status.get('alerts') or {}).get('status'))}</p>

  <h2>Resumo</h2>
  <table>
    <tr><th>Hosts</th><td>{esc(summary.get('hosts_success'))}/{esc(summary.get('hosts_total'))}</td></tr>
    <tr><th>Containers</th><td>{esc(summary.get('containers_total'))}</td></tr>
    <tr><th>Imagens</th><td>{esc(summary.get('images_total'))}</td></tr>
    <tr><th>Achados</th><td>{esc(summary.get('findings_total'))}</td></tr>
    <tr><th>Vulnerabilidades</th><td>{esc(vulns.get('total'))}</td></tr>
    <tr><th>Vulnerabilidades DT</th><td>{esc(((status.get('dependency_track') or {}).get('analysis_totals') or {}).get('dtrack_vulnerabilities', 0))}</td></tr>
    <tr><th>Alertas ativos</th><td>{esc(((status.get('alerts') or {}).get('totals') or {}).get('active', 0))}</td></tr>
    <tr><th>Severidades</th><td>{esc(vulns.get('severity_counts'))}</td></tr>
  </table>

  <h2>Links</h2>
  <ul>
    <li><a href="/reports/executive">Relatorio gerencial</a></li>
    <li><a href="/reports/technical">Relatorio tecnico</a></li>
    <li><a href="/api/status">API status JSON</a></li>
    <li><a href="/metrics">Prometheus metrics</a></li>
    <li><a href="http://192.168.1.22:8080">Dependency-Track</a></li>
  </ul>

  <h2>Top Riscos</h2>
  <table>
    <tr><th>Score</th><th>Classe</th><th>Contexto</th><th>Host</th><th>Container</th><th>Imagem</th></tr>
    {''.join(top_rows)}
  </table>

  <h2>Contextos Prioritarios</h2>
  <table>
    <tr><th>Contexto</th><th>Containers</th><th>Score Max</th><th>Score Medio</th><th>Achados</th><th>Criticos</th><th>Altos</th></tr>
    {''.join(
        f"<tr><td>{esc(item.get('context'))}</td><td>{esc(item.get('containers'))}</td><td>{esc(item.get('score_max'))}</td><td>{esc(item.get('score_avg'))}</td><td>{esc(item.get('findings'))}</td><td>{esc(item.get('critical_containers'))}</td><td>{esc(item.get('high_containers'))}</td></tr>"
        for item in (status.get('context_summary') or [])
    )}
  </table>
</body>
</html>
"""


def main():
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"serving Container Security Monitor on http://{BIND}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
