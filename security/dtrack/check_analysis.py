#!/usr/bin/env python3
import argparse
import json
import os
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, parse, request


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
    values.update({key: value for key, value in os.environ.items() if key.startswith("DTRACK_")})
    return values


def latest(path, pattern, run_id):
    exact = path / pattern.format(run_id=run_id)
    if exact.exists():
        return exact
    candidates = sorted(path.glob(pattern.format(run_id="*")))
    return candidates[-1] if candidates else None


def split_image_ref(image):
    if "@" in image:
        name, digest = image.split("@", 1)
        return name, digest
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = image.rsplit(":", 1)
        return name, tag
    return image, "latest"


def api_get_json(base_url, api_key, path, timeout, insecure_tls):
    context = ssl._create_unverified_context() if insecure_tls else None
    req = request.Request(
        base_url.rstrip("/") + path,
        headers={
            "X-Api-Key": api_key,
            "Accept": "application/json",
            "User-Agent": "container-security-monitor/0.1",
        },
    )
    with request.urlopen(req, timeout=timeout, context=context) as response:
        payload = response.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            data = payload
        return data, response.headers


def normalize_project_list(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("items", "projects", "data"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


def expected_projects(upload_summary):
    projects = []
    for item in upload_summary.get("results", []) or []:
        if item.get("status") != "uploaded" or not item.get("image"):
            continue
        name, version = split_image_ref(item["image"])
        projects.append({"image": item["image"], "name": name, "version": version})
    return projects


def trivy_total(root, run_id):
    path = latest(root / "output" / "history", "risk_scores_{run_id}.json", run_id)
    if path:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return int((data.get("vulnerability_summary") or {}).get("total") or 0)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    return 0


def collect_once(root, run_id, dtrack_url, api_key, timeout, insecure_tls):
    upload_path = latest(root / "output" / "dtrack", "dtrack_upload_{run_id}.json", run_id)
    upload_summary = json.loads(upload_path.read_text(encoding="utf-8")) if upload_path else {}
    expected = expected_projects(upload_summary)

    projects_payload, _ = api_get_json(dtrack_url, api_key, "/api/v1/project?pageSize=500", timeout, insecure_tls)
    all_projects = normalize_project_list(projects_payload)
    by_name_version = {
        (project.get("name"), project.get("version")): project
        for project in all_projects
        if isinstance(project, dict)
    }

    rows = []
    totals = {
        "expected_projects": len(expected),
        "found_projects": 0,
        "dtrack_vulnerabilities": 0,
        "dtrack_critical": 0,
        "dtrack_high": 0,
        "dtrack_vulnerable_components": 0,
        "dtrack_components": 0,
    }
    for wanted in expected:
        project = by_name_version.get((wanted["name"], wanted["version"]))
        row = dict(wanted)
        if not project:
            row.update({"status": "project_not_found"})
            rows.append(row)
            continue

        totals["found_projects"] += 1
        uuid = project.get("uuid")
        row.update({
            "status": "found",
            "uuid": uuid,
            "lastBomImport": project.get("lastBomImport"),
        })
        if uuid:
            metric_path = f"/api/v1/metrics/project/{parse.quote(uuid)}/current"
            try:
                metrics, _ = api_get_json(dtrack_url, api_key, metric_path, timeout, insecure_tls)
                if isinstance(metrics, dict):
                    vuln_count = int(metrics.get("vulnerabilities") or 0)
                    critical = int(metrics.get("critical") or 0)
                    high = int(metrics.get("high") or 0)
                    vulnerable_components = int(metrics.get("vulnerableComponents") or 0)
                    components = int(metrics.get("components") or project.get("metrics", {}).get("components") or 0)
                    row["metrics"] = {
                        "components": components,
                        "vulnerabilities": vuln_count,
                        "critical": critical,
                        "high": high,
                        "vulnerableComponents": vulnerable_components,
                    }
                    totals["dtrack_vulnerabilities"] += vuln_count
                    totals["dtrack_critical"] += critical
                    totals["dtrack_high"] += high
                    totals["dtrack_vulnerable_components"] += vulnerable_components
                    totals["dtrack_components"] += components
            except Exception as exc:
                row["metrics_error"] = str(exc)[-1000:]
        rows.append(row)
    return upload_summary, totals, rows


def main():
    parser = argparse.ArgumentParser(description="Check Dependency-Track vulnerability correlation after SBOM upload.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--poll-seconds", type=int, default=0)
    parser.add_argument("--poll-interval", type=int, default=15)
    args = parser.parse_args()

    root = Path(args.root)
    env_path = root / "config" / "dependency-track.env"
    config = load_env(env_path)
    dtrack_url = config.get("DTRACK_URL", "").strip()
    api_key = config.get("DTRACK_API_KEY", "").strip()
    insecure_tls = config.get("DTRACK_INSECURE_TLS", "false").lower() == "true"

    out_dir = root / "output" / "dtrack"
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / f"dtrack_analysis_{args.run_id}.json"

    summary = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "status": "unknown",
        "configured": bool(dtrack_url and api_key),
        "source_note": "Trivy is the local vulnerability source used by scanner reports; Dependency-Track reports only vulnerabilities it correlates from imported SBOM components.",
        "trivy_vulnerabilities": trivy_total(root, args.run_id),
        "totals": {},
        "projects": [],
    }

    if not dtrack_url or not api_key:
        summary["status"] = "skipped_not_configured"
        output_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        print("Dependency-Track not configured; skipping analysis check")
        return 0

    deadline = time.monotonic() + max(args.poll_seconds, 0)
    first = True
    last_error = None
    while first or time.monotonic() < deadline:
        first = False
        try:
            upload_summary, totals, rows = collect_once(root, args.run_id, dtrack_url, api_key, args.timeout, insecure_tls)
            summary["upload_status"] = upload_summary.get("status")
            summary["totals"] = totals
            summary["projects"] = rows
            if totals["found_projects"] >= totals["expected_projects"] and totals["expected_projects"]:
                if totals["dtrack_vulnerabilities"] > 0:
                    break
                if args.poll_seconds <= 0:
                    break
            last_error = None
        except error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
        except Exception as exc:
            last_error = str(exc)[-1000:]
        if time.monotonic() < deadline:
            time.sleep(max(args.poll_interval, 1))

    if last_error:
        summary["status"] = "failed"
        summary["error"] = last_error
    else:
        totals = summary.get("totals") or {}
        if not totals.get("expected_projects"):
            summary["status"] = "skipped_no_uploaded_sboms"
        elif totals.get("found_projects", 0) < totals.get("expected_projects", 0):
            summary["status"] = "pending_project_import"
        elif totals.get("dtrack_vulnerabilities", 0) > 0:
            summary["status"] = "matched"
        elif summary.get("trivy_vulnerabilities", 0) > 0:
            summary["status"] = "correlation_gap"
            summary["recommendation"] = (
                "Use the Trivy report as the vulnerability source of truth for this run. "
                "Dependency-Track imported the SBOMs but did not correlate vulnerabilities for these components."
            )
        else:
            summary["status"] = "no_vulnerabilities_detected"

    output_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    latest_path = out_dir / "dtrack_analysis_latest.json"
    latest_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] != "failed" else 1


if __name__ == "__main__":
    sys.exit(main())
