#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_env(path):
    values = {}
    if path.exists():
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def latest(path, pattern, run_id):
    exact = path / pattern.format(run_id=run_id)
    if exact.exists():
        return exact
    candidates = sorted(path.glob(pattern.format(run_id="*")))
    return candidates[-1] if candidates else None


def metric_name(value):
    return re.sub(r"[^a-zA-Z0-9_:]", "_", value)


def label_value(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def prom_line(name, value, labels=None):
    labels = {"channel": "grafana", **(labels or {})}
    label_text = ""
    if labels:
        rendered = ",".join(f'{metric_name(k)}="{label_value(v)}"' for k, v in sorted(labels.items()))
        label_text = "{" + rendered + "}"
    return f"{metric_name(name)}{label_text} {value}"


def zabbix_line(host, key, value):
    value = str(value).replace("\n", " ")
    return f'"{host}" {key} {value}'


def main():
    parser = argparse.ArgumentParser(description="Export scan metrics for Prometheus textfile and optional Zabbix sender.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()

    root = Path(args.root)
    inventory_path = latest(root / "output" / "inventory", "inventory_{run_id}.json", args.run_id)
    risk_path = latest(root / "output" / "history", "risk_scores_{run_id}.json", args.run_id)
    trivy_path = latest(root / "output" / "trivy", "trivy_summary_{run_id}.json", args.run_id)
    dtrack_path = latest(root / "output" / "dtrack", "dtrack_upload_{run_id}.json", args.run_id)
    dtrack_analysis_path = latest(root / "output" / "dtrack", "dtrack_analysis_{run_id}.json", args.run_id)
    alerts_path = latest(root / "output" / "alerts", "alerts_{run_id}.json", args.run_id)

    if not inventory_path or not risk_path:
        print("inventory or risk scores not found; cannot export metrics", file=sys.stderr)
        return 2

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    risk = json.loads(risk_path.read_text(encoding="utf-8"))
    trivy = json.loads(trivy_path.read_text(encoding="utf-8")) if trivy_path else {}
    dtrack = json.loads(dtrack_path.read_text(encoding="utf-8")) if dtrack_path else {}
    dtrack_analysis = json.loads(dtrack_analysis_path.read_text(encoding="utf-8")) if dtrack_analysis_path else {}
    alerts = json.loads(alerts_path.read_text(encoding="utf-8")) if alerts_path else {}

    inv_summary = inventory.get("summary", {})
    vuln_summary = risk.get("vulnerability_summary", {})
    scores = risk.get("scores", [])
    max_score = max([item.get("score", 0) for item in scores] or [0])
    critical_containers = sum(1 for item in scores if item.get("classification") == "critico")
    high_containers = sum(1 for item in scores if item.get("classification") == "alto")
    scan_status = effective_scan_status(inventory, trivy, dtrack)
    dtrack_totals = dtrack_analysis.get("totals") or {}
    alert_totals = alerts.get("totals") or {}
    context_stats = aggregate_context_stats(scores)

    metrics_dir = root / "output" / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)

    prom = [
        "# HELP container_security_info Static scan metadata.",
        "# TYPE container_security_info gauge",
        prom_line("container_security_info", 1, {"run_id": args.run_id, "generated_at": utc_now()}),
        "# HELP container_security_scan_status 0 success, 1 partial_success, 2 failed.",
        "# TYPE container_security_scan_status gauge",
        prom_line("container_security_scan_status", scan_status),
        prom_line("container_security_hosts_total", inv_summary.get("hosts_total", 0)),
        prom_line("container_security_hosts_success", inv_summary.get("hosts_success", 0)),
        prom_line("container_security_containers_total", inv_summary.get("containers_total", 0)),
        prom_line("container_security_images_total", inv_summary.get("images_total", 0)),
        prom_line("container_security_findings_total", inv_summary.get("findings_total", 0)),
        prom_line("container_security_risk_score_max", max_score),
        prom_line("container_security_containers_critical", critical_containers),
        prom_line("container_security_containers_high", high_containers),
        prom_line("container_security_trivy_images_total", trivy.get("images_total", 0)),
        prom_line("container_security_trivy_images_success", trivy.get("success", 0)),
        prom_line("container_security_trivy_images_failed", trivy.get("failed", 0)),
        prom_line("container_security_dtrack_uploaded", dtrack.get("uploaded", 0)),
        prom_line("container_security_dtrack_failed", dtrack.get("failed", 0)),
        prom_line("container_security_dtrack_vulnerabilities", dtrack_totals.get("dtrack_vulnerabilities", 0)),
        prom_line("container_security_dtrack_vulnerable_components", dtrack_totals.get("dtrack_vulnerable_components", 0)),
        prom_line("container_security_alerts_total", alert_totals.get("active", 0)),
        prom_line("container_security_alerts_critical", alert_totals.get("critical", 0)),
        prom_line("container_security_alerts_warning", alert_totals.get("warning", 0)),
        prom_line(
            "container_security_dtrack_correlation_gap",
            1 if any(alert.get("id") == "dtrack_correlation_gap" and alert.get("active") for alert in (alerts.get("rules") or alerts.get("alerts") or [])) else 0,
        ),
    ]
    for context, stats in sorted(context_stats.items()):
        prom.append(prom_line("container_security_context_container_count", stats["containers"], {"context": context}))
        prom.append(prom_line("container_security_context_risk_score_max", stats["score_max"], {"context": context}))
        prom.append(prom_line("container_security_context_risk_score_avg", stats["score_avg"], {"context": context}))
        prom.append(prom_line("container_security_context_findings_total", stats["findings"], {"context": context}))
        prom.append(prom_line("container_security_context_critical_containers", stats["critical"], {"context": context}))
        prom.append(prom_line("container_security_context_high_containers", stats["high"], {"context": context}))

    for severity, count in sorted((inv_summary.get("findings_by_severity") or {}).items()):
        prom.append(prom_line("container_security_findings_by_severity", count, {"severity": severity}))
    for severity, count in sorted((vuln_summary.get("severity_counts") or {}).items()):
        prom.append(prom_line("container_security_vulnerabilities_by_severity", count, {"severity": severity.lower()}))
    for item in scores[:20]:
        prom.append(prom_line(
            "container_security_container_risk_score",
            item.get("score", 0),
            {
                "host": item.get("host_name", "unknown"),
                "container": item.get("container_name", "unknown"),
                "classification": item.get("classification", "unknown"),
                "context": item.get("context", "docker default"),
            },
        ))
    for alert in (alerts.get("rules") or alerts.get("alerts") or []):
        state = "triggered" if alert.get("active") else "ok"
        prom.append(prom_line(
            "container_security_alert_rule_violation",
            1 if alert.get("active") else 0,
            {
                "rule": alert.get("id", "unknown"),
                "severity": alert.get("severity", "unknown"),
                "channel": alert.get("channel", "grafana"),
                "state": state,
            },
        ))
        prom.append(prom_line(
            "container_security_alert_rule_state",
            1 if alert.get("active") else 0,
            {
                "rule": alert.get("id", "unknown"),
                "severity": alert.get("severity", "unknown"),
                "channel": alert.get("channel", "grafana"),
                "state": state,
            },
        ))

    prom_path = metrics_dir / f"container_security_{args.run_id}.prom"
    latest_prom = metrics_dir / "container_security_latest.prom"
    prom_content = "\n".join(prom) + "\n"
    prom_path.write_text(prom_content, encoding="utf-8")
    latest_prom.write_text(prom_content, encoding="utf-8")

    zabbix_host = load_env(root / "config" / "zabbix.env").get("ZABBIX_HOST", "container-security-monitor")
    zabbix_lines = [
        zabbix_line(zabbix_host, "container.security.scan_status", scan_status),
        zabbix_line(zabbix_host, "container.security.total_containers", inv_summary.get("containers_total", 0)),
        zabbix_line(zabbix_host, "container.security.total_images", inv_summary.get("images_total", 0)),
        zabbix_line(zabbix_host, "container.security.findings_total", inv_summary.get("findings_total", 0)),
        zabbix_line(zabbix_host, "container.security.risk_score", max_score),
        zabbix_line(zabbix_host, "container.security.critical_vulns", (vuln_summary.get("severity_counts") or {}).get("CRITICAL", 0)),
        zabbix_line(zabbix_host, "container.security.high_vulns", (vuln_summary.get("severity_counts") or {}).get("HIGH", 0)),
        zabbix_line(zabbix_host, "container.security.failed_scans", trivy.get("failed", 0)),
        zabbix_line(zabbix_host, "container.security.dtrack_failed", dtrack.get("failed", 0)),
        zabbix_line(zabbix_host, "container.security.dtrack_vulns", dtrack_totals.get("dtrack_vulnerabilities", 0)),
    ]
    zabbix_path = metrics_dir / f"zabbix_sender_{args.run_id}.txt"
    latest_zabbix = metrics_dir / "zabbix_sender_latest.txt"
    zabbix_content = "\n".join(zabbix_lines) + "\n"
    zabbix_path.write_text(zabbix_content, encoding="utf-8")
    latest_zabbix.write_text(zabbix_content, encoding="utf-8")

    sender_status = maybe_send_zabbix(root, zabbix_path)
    summary = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "prometheus_textfile": str(prom_path),
        "prometheus_latest": str(latest_prom),
        "zabbix_payload": str(zabbix_path),
        "zabbix_latest": str(latest_zabbix),
        "zabbix_sender_status": sender_status,
        "dependency_track_analysis": {
            "status": dtrack_analysis.get("status"),
            "totals": dtrack_totals,
        },
        "alerts": {
            "status": alerts.get("status"),
            "totals": alert_totals,
            "active_rules": alerts.get("alerts", []),
        },
    }
    (metrics_dir / f"metrics_summary_{args.run_id}.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if sender_status.get("status") in ("skipped_not_configured", "sent") else 1


def maybe_send_zabbix(root, payload_path):
    config = load_env(root / "config" / "zabbix.env")
    if config.get("ZABBIX_ENABLED", "false").lower() != "true":
        return {"status": "skipped_not_configured"}
    if not shutil.which("zabbix_sender"):
        return {"status": "failed_missing_zabbix_sender"}
    server = config.get("ZABBIX_SERVER")
    host = config.get("ZABBIX_HOST")
    if not server or not host:
        return {"status": "failed_invalid_config"}
    cmd = ["zabbix_sender", "-z", server, "-i", str(payload_path)]
    if config.get("ZABBIX_PORT"):
        cmd.extend(["-p", config["ZABBIX_PORT"]])
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=60)
    return {
        "status": "sent" if proc.returncode == 0 else "failed",
        "returncode": proc.returncode,
        "stdout": proc.stdout[-2000:],
        "stderr": proc.stderr[-2000:],
    }


def effective_scan_status(inventory, trivy, dtrack):
    if inventory.get("status") == "failed":
        return 2
    if inventory.get("status") == "partial_success":
        return 1
    if trivy.get("failed", 0):
        return 1
    if dtrack.get("status") in ("failed", "partial_success"):
        return 1
    return 0


def aggregate_context_stats(scores):
    stats = {}
    for item in scores:
        context = item.get("context") or "docker default"
        row = stats.setdefault(context, {
            "containers": 0,
            "score_max": 0,
            "score_sum": 0,
            "score_avg": 0,
            "findings": 0,
            "critical": 0,
            "high": 0,
        })
        score = item.get("score", 0) or 0
        row["containers"] += 1
        row["score_sum"] += score
        row["score_max"] = max(row["score_max"], score)
        row["findings"] += item.get("findings", 0) or 0
        if item.get("classification") == "critico":
            row["critical"] += 1
        if item.get("classification") == "alto":
            row["high"] += 1
    for row in stats.values():
        row["score_avg"] = round(row["score_sum"] / row["containers"], 2) if row["containers"] else 0
    return stats


if __name__ == "__main__":
    sys.exit(main())
