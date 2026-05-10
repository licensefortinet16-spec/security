#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


DEFAULTS = {
    "logs_days": 90,
    "reports_days": 365,
    "sbom_days": 365,
    "trivy_json_days": 180,
    "inventory_days": 180,
    "history_days": 730,
    "metrics_days": 180,
    "image_sync_days": 180,
    "backups_days": 30,
    "tmp_days": 7,
    "docker_prune_unused_synced_images": False,
}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_policy(path):
    policy = DEFAULTS.copy()
    if not path.exists():
        return policy
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line or line == "retention:":
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key not in policy:
            continue
        if value.lower() in ("true", "false"):
            policy[key] = value.lower() == "true"
        else:
            try:
                policy[key] = int(value)
            except ValueError:
                pass
    return policy


def delete_old_files(path, days, keep_latest_names=None):
    keep_latest_names = set(keep_latest_names or [])
    if not path.exists():
        return []
    cutoff = time.time() - (days * 86400)
    deleted = []
    for item in path.rglob("*"):
        if not item.is_file() or item.name in keep_latest_names:
            continue
        if item.stat().st_mtime < cutoff:
            item.unlink()
            deleted.append(str(item))
    return deleted


def delete_empty_dirs(path):
    if not path.exists():
        return []
    removed = []
    for item in sorted(path.rglob("*"), reverse=True):
        if item.is_dir():
            try:
                item.rmdir()
                removed.append(str(item))
            except OSError:
                pass
    return removed


def current_images_from_inventory(root):
    inventories = sorted((root / "output" / "inventory").glob("inventory_*.json"))
    if not inventories:
        return set()
    data = json.loads(inventories[-1].read_text(encoding="utf-8"))
    images = set()
    for host in data.get("hosts", []):
        for container in host.get("containers", []):
            if container.get("image"):
                images.add(container["image"])
    return images


def prune_unused_images(root):
    current = current_images_from_inventory(root)
    if not current:
        return []
    proc = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], text=True, capture_output=True, timeout=60)
    if proc.returncode != 0:
        return []
    removed = []
    for image in proc.stdout.splitlines():
        if not image or image.endswith(":<none>") or image in current:
            continue
        rm = subprocess.run(["docker", "image", "rm", image], text=True, capture_output=True, timeout=120)
        if rm.returncode == 0:
            removed.append(image)
    return removed


def main():
    parser = argparse.ArgumentParser(description="Apply retention policy for Container Security Monitor outputs.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security"))
    args = parser.parse_args()
    root = Path(args.root)
    policy = load_policy(root / "config" / "retention_policy.yml")
    output = root / "output"

    deleted = {}
    deleted["logs"] = delete_old_files(output / "logs", policy["logs_days"])
    deleted["reports"] = delete_old_files(output / "reports", policy["reports_days"], {
        "index.html",
        "executive_report_latest.html",
        "technical_report_latest.html",
        "priorities_latest.csv",
        "priorities_latest.json",
    })
    deleted["sbom"] = delete_old_files(output / "sbom", policy["sbom_days"])
    deleted["trivy"] = delete_old_files(output / "trivy", policy["trivy_json_days"])
    deleted["inventory"] = delete_old_files(output / "inventory", policy["inventory_days"])
    deleted["history"] = delete_old_files(output / "history", policy["history_days"], {"risk_scores_latest.json"})
    deleted["metrics"] = delete_old_files(output / "metrics", policy["metrics_days"], {
        "container_security_latest.prom",
        "zabbix_sender_latest.txt",
    })
    deleted["image_sync"] = delete_old_files(output / "image-sync", policy["image_sync_days"])
    deleted["backups"] = delete_old_files(output / "backups", policy["backups_days"])
    deleted["tmp"] = delete_old_files(root / "tmp", policy["tmp_days"])
    deleted["empty_dirs"] = delete_empty_dirs(root / "tmp")
    deleted["docker_images"] = prune_unused_images(root) if policy["docker_prune_unused_synced_images"] else []

    summary = {
        "generated_at": utc_now(),
        "policy": policy,
        "deleted_counts": {key: len(value) for key, value in deleted.items()},
        "deleted": deleted,
    }
    cleanup_dir = output / "cleanup"
    cleanup_dir.mkdir(parents=True, exist_ok=True)
    path = cleanup_dir / f"cleanup_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"summary": summary["deleted_counts"], "log": str(path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
