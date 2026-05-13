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


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "unknown"


def latest_inventory(root, run_id):
    exact = root / "output" / "inventory" / f"inventory_{run_id}.json"
    if exact.exists():
        return exact
    candidates = sorted((root / "output" / "inventory").glob("inventory_*.json"))
    return candidates[-1] if candidates else None


def image_refs(inventory):
    refs = set()
    for host in inventory.get("hosts", []):
        for container in host.get("containers", []):
            ref = container.get("image")
            if ref:
                refs.add(ref)
    return sorted(refs)


def run_trivy(root, run_id, image):
    output_dir = root / "output" / "trivy"
    sbom_dir = root / "output" / "sbom"
    tmp_dir = root / "tmp" / "trivy"
    cache_dir = root / ".cache" / "trivy"
    output_dir.mkdir(parents=True, exist_ok=True)
    sbom_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    base = safe_name(image)
    vuln_path = output_dir / f"trivy_{base}_{run_id}.json"
    sbom_path = sbom_dir / f"sbom_{base}_{run_id}.cdx.json"

    vuln_cmd = [
        "trivy",
        "image",
        "--quiet",
        "--cache-dir",
        str(cache_dir),
        "--format",
        "json",
        "--output",
        str(vuln_path),
        image,
    ]
    sbom_cmd = [
        "trivy",
        "image",
        "--quiet",
        "--cache-dir",
        str(cache_dir),
        "--format",
        "cyclonedx",
        "--output",
        str(sbom_path),
        image,
    ]

    env = os.environ.copy()
    env["TMPDIR"] = str(tmp_dir)

    vuln = subprocess.run(vuln_cmd, text=True, capture_output=True, timeout=900, env=env)
    if vuln.returncode != 0:
        return {
            "image": image,
            "status": "image_unavailable_for_central_scan",
            "stage": "trivy_vulnerability_scan",
            "stderr": sanitize(vuln.stderr),
            "output": str(vuln_path),
        }

    sbom = subprocess.run(sbom_cmd, text=True, capture_output=True, timeout=900, env=env)
    if sbom.returncode != 0:
        return {
            "image": image,
            "status": "sbom_failed",
            "stage": "trivy_sbom",
            "stderr": sanitize(sbom.stderr),
            "vulnerability_output": str(vuln_path),
            "sbom_output": str(sbom_path),
        }

    return {
        "image": image,
        "status": "success",
        "vulnerability_output": str(vuln_path),
        "sbom_output": str(sbom_path),
    }


def sanitize(value):
    text = value or ""
    text = re.sub(r"(?i)(api[_-]?key|token|password|secret)=\S+", r"\1=<redacted>", text)
    return text[-4000:]


def main():
    parser = argparse.ArgumentParser(description="Run Trivy image scans only on the central server.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()

    if not shutil.which("trivy"):
        print("trivy is not installed on the central server", file=sys.stderr)
        return 1

    root = Path(args.root)
    inventory_path = latest_inventory(root, args.run_id)
    if not inventory_path:
        print("inventory not found; run docker_inventory.py first", file=sys.stderr)
        return 2

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    results = []
    for image in image_refs(inventory):
        print(f"central_trivy_scan image={image}", flush=True)
        results.append(run_trivy(root, args.run_id, image))

    summary = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "central_only": True,
        "images_total": len(results),
        "success": sum(1 for item in results if item.get("status") == "success"),
        "failed": sum(1 for item in results if item.get("status") != "success"),
        "results": results,
    }

    out = root / "output" / "trivy" / f"trivy_summary_{args.run_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    if summary["success"] == summary["images_total"]:
        return 0
    if summary["success"] > 0:
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
