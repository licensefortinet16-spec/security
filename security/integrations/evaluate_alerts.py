#!/usr/bin/env python3
import argparse
import json
import os
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def latest(path, pattern, run_id):
    exact = path / pattern.format(run_id=run_id)
    if exact.exists():
        return exact
    candidates = sorted(path.glob(pattern.format(run_id="*")))
    return candidates[-1] if candidates else None


def load_json(path, default=None):
    if not path or not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def get_path(data, dotted):
    current = data
    for part in dotted.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def coerce_number(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            return value
    return value


def escape_label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def evaluate_rule(value, operator, threshold):
    value = coerce_number(value)
    threshold = coerce_number(threshold)

    if operator == "gt":
        if value is None or threshold is None:
            return False
        return value > threshold
    if operator == "gte":
        if value is None or threshold is None:
            return False
        return value >= threshold
    if operator == "lt":
        if value is None or threshold is None:
            return False
        return value < threshold
    if operator == "lte":
        if value is None or threshold is None:
            return False
        return value <= threshold
    if operator == "eq":
        if value is None or threshold is None:
            return False
        return value == threshold
    if operator == "ne":
        if value is None or threshold is None:
            return False
        return value != threshold
    if operator == "contains":
        if isinstance(value, (list, tuple, set)):
            return threshold in value
        return str(threshold) in str(value)
    if operator == "truthy":
        return bool(value)
    raise ValueError(f"unsupported operator: {operator}")


def load_policy(root):
    policy_path = root / "config" / "alert_policy.toml"
    if not policy_path.exists():
        return {"settings": {"enabled": False}, "rules": []}
    return tomllib.loads(policy_path.read_text(encoding="utf-8"))


def build_context(root, run_id):
    inventory = load_json(latest(root / "output" / "inventory", "inventory_{run_id}.json", run_id), {})
    risk = load_json(latest(root / "output" / "history", "risk_scores_{run_id}.json", run_id), {})
    dtrack = load_json(latest(root / "output" / "dtrack", "dtrack_upload_{run_id}.json", run_id), {})
    dtrack_analysis = load_json(latest(root / "output" / "dtrack", "dtrack_analysis_{run_id}.json", run_id), {})
    trivy = load_json(latest(root / "output" / "trivy", "trivy_summary_{run_id}.json", run_id), {})
    code = load_json(latest(root / "output" / "code", "code_summary_{run_id}.json", run_id), {})

    scores = risk.get("scores", []) or []
    vuln_summary = risk.get("vulnerability_summary", {}) or {}
    severity_counts = vuln_summary.get("severity_counts", {}) or {}
    hosts = inventory.get("hosts", []) or []
    contexts = []
    for host in hosts:
        contexts.extend(host.get("contexts", []) or [])
    unscannable_contexts = [
        item for item in contexts
        if item.get("status") not in (None, "", "success")
    ]

    derived = {
        "max_risk_score": max((item.get("score", 0) for item in scores), default=0),
        "critical_containers": sum(1 for item in scores if item.get("classification") == "critico"),
        "high_containers": sum(1 for item in scores if item.get("classification") == "alto"),
        "critical_vulnerabilities": int(severity_counts.get("CRITICAL", 0) or 0),
        "high_vulnerabilities": int(severity_counts.get("HIGH", 0) or 0),
        "medium_vulnerabilities": int(severity_counts.get("MEDIUM", 0) or 0),
        "low_vulnerabilities": int(severity_counts.get("LOW", 0) or 0),
        "unscannable_contexts": len(unscannable_contexts),
        "unscannable_context_names": [item.get("name") for item in unscannable_contexts if item.get("name")],
        "unscannable_context_statuses": [item.get("status") for item in unscannable_contexts if item.get("status")],
        "scan_failed": int(trivy.get("failed", 0) or 0)
        + int(dtrack.get("failed", 0) or 0)
        + int(code.get("failed", 0) or 0)
        + (1 if inventory.get("status") == "failed" else 0),
        "code_secrets": int((code.get("totals") or {}).get("secrets", 0) or 0),
        "code_high_findings": int(((code.get("totals") or {}).get("severity_counts") or {}).get("HIGH", 0) or 0),
        "code_critical_findings": int(((code.get("totals") or {}).get("severity_counts") or {}).get("CRITICAL", 0) or 0),
    }

    return {
        "inventory": inventory,
        "risk": risk,
        "trivy": trivy,
        "code": code,
        "dtrack": dtrack,
        "dtrack_analysis": dtrack_analysis,
        "derived": derived,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate non-blocking security alert rules and export Grafana-friendly state.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()

    root = Path(args.root)
    policy = load_policy(root)
    context = build_context(root, args.run_id)
    out_dir = root / "output" / "alerts"
    out_dir.mkdir(parents=True, exist_ok=True)

    all_rules = []
    active_rules = []
    for rule in policy.get("rules", []):
        value = get_path(context, rule.get("path", ""))
        matched = evaluate_rule(value, rule.get("operator", "truthy"), rule.get("threshold"))
        entry = {
            "id": rule.get("id"),
            "severity": rule.get("severity", "warning"),
            "channel": rule.get("channel", "grafana"),
            "path": rule.get("path"),
            "operator": rule.get("operator"),
            "threshold": rule.get("threshold"),
            "message": rule.get("message", ""),
            "observed": value,
            "active": bool(matched),
        }
        all_rules.append(entry)
        if matched:
            active_rules.append(entry)

    totals = {
        "active": len(active_rules),
        "critical": sum(1 for item in active_rules if item.get("severity") == "critical"),
        "warning": sum(1 for item in active_rules if item.get("severity") == "warning"),
        "info": sum(1 for item in active_rules if item.get("severity") == "info"),
    }

    summary = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "configured": bool(policy.get("settings", {}).get("enabled", True)),
        "status": "alerting" if active_rules else "ok",
        "totals": totals,
        "derived": context["derived"],
        "rules": all_rules,
        "alerts": active_rules,
        "recommendation": "Grafana deve exibir os estados ativos; nenhum bloqueio e aplicado por estas regras.",
    }

    latest_json = out_dir / "alerts_latest.json"
    run_json = out_dir / f"alerts_{args.run_id}.json"
    latest_json.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    run_json.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    prom_lines = [
        "# HELP container_security_alerts_total Active non-blocking alert rules.",
        "# TYPE container_security_alerts_total gauge",
        f"container_security_alerts_total {totals['active']}",
        "# HELP container_security_alerts_critical Critical active alert rules.",
        "# TYPE container_security_alerts_critical gauge",
        f"container_security_alerts_critical {totals['critical']}",
        "# HELP container_security_alerts_warning Warning active alert rules.",
        "# TYPE container_security_alerts_warning gauge",
        f"container_security_alerts_warning {totals['warning']}",
        "# HELP container_security_dtrack_correlation_gap Dependency-Track correlation gap status.",
        "# TYPE container_security_dtrack_correlation_gap gauge",
        f"container_security_dtrack_correlation_gap {1 if any(item.get('id') == 'dtrack_correlation_gap' and item.get('active') for item in all_rules) else 0}",
    ]
    for item in all_rules:
        state = "triggered" if item.get("active") else "ok"
        labels = ",".join(
            f'{key}="{escape_label(value)}"'
            for key, value in sorted({
                "rule": item["id"],
                "severity": item["severity"],
                "channel": item["channel"],
                "state": state,
            }.items())
        )
        prom_lines.append(
            f"container_security_alert_rule_violation{{{labels}}} {1 if item.get('active') else 0}"
        )
        prom_lines.append(
            f"container_security_alert_rule_state{{{labels}}} {1 if item.get('active') else 0}"
        )
    (out_dir / f"alerts_{args.run_id}.prom").write_text("\n".join(prom_lines) + "\n", encoding="utf-8")
    (out_dir / "alerts_latest.prom").write_text("\n".join(prom_lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
