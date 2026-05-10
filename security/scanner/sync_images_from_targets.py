#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,255}$")


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def latest_inventory(root, run_id):
    exact = root / "output" / "inventory" / f"inventory_{run_id}.json"
    if exact.exists():
        return exact
    candidates = sorted((root / "output" / "inventory").glob("inventory_*.json"))
    return candidates[-1] if candidates else None


def run(cmd, timeout=60):
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)


def central_has_image(image):
    return run(["docker", "image", "inspect", image], timeout=30).returncode == 0


def safe_image_ref(image):
    return bool(image and IMAGE_REF_RE.match(image))


def sync_image(host, image, timeout):
    user = host.get("ssh_user", "root")
    remote = f"{user}@{host['ip']}"
    ssh_cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        remote,
        "docker",
        "save",
        image,
    ]
    load_cmd = ["docker", "load"]

    save_proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    load_proc = subprocess.Popen(load_cmd, stdin=save_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if save_proc.stdout:
        save_proc.stdout.close()

    try:
        load_stdout, load_stderr = load_proc.communicate(timeout=timeout)
        save_stderr = save_proc.stderr.read() if save_proc.stderr else b""
        save_return = save_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        save_proc.kill()
        load_proc.kill()
        return {"status": "sync_failed_timeout"}

    if save_return != 0 or load_proc.returncode != 0:
        return {
            "status": "sync_failed",
            "save_returncode": save_return,
            "load_returncode": load_proc.returncode,
            "save_stderr": sanitize(save_stderr.decode("utf-8", errors="replace")),
            "load_stderr": sanitize(load_stderr.decode("utf-8", errors="replace")),
            "load_stdout": sanitize(load_stdout.decode("utf-8", errors="replace")),
        }

    return {
        "status": "synced",
        "save_returncode": save_return,
        "load_returncode": load_proc.returncode,
        "load_stdout": sanitize(load_stdout.decode("utf-8", errors="replace")),
    }


def sanitize(value):
    text = value or ""
    text = re.sub(r"(?i)(api[_-]?key|token|password|secret)=\S+", r"\1=<redacted>", text)
    return text[-4000:]


def image_hosts(inventory):
    rows = []
    for host_result in inventory.get("hosts", []):
        if host_result.get("status") != "success":
            continue
        host = host_result.get("host") or {}
        seen = set()
        for container in host_result.get("containers", []):
            image = container.get("image")
            if not image or image in seen:
                continue
            seen.add(image)
            rows.append({"host": host, "image": image, "container": container.get("name")})
    return rows


def main():
    parser = argparse.ArgumentParser(description="Synchronize target Docker images to central server using docker save over SSH.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()

    root = Path(args.root)
    inventory_path = latest_inventory(root, args.run_id)
    if not inventory_path:
        print("inventory not found; cannot sync images", file=sys.stderr)
        return 2

    if run(["docker", "version"], timeout=30).returncode != 0:
        print("central docker is not available; cannot sync images", file=sys.stderr)
        return 1

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    output = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "status": "unknown",
        "synced": 0,
        "skipped_existing": 0,
        "skipped_invalid": 0,
        "failed": 0,
        "results": [],
    }

    for row in image_hosts(inventory):
        image = row["image"]
        host = row["host"]
        result = {
            "image": image,
            "host_name": host.get("name"),
            "host_ip": host.get("ip"),
            "container": row.get("container"),
        }
        if not safe_image_ref(image):
            result["status"] = "skipped_invalid_image_ref"
            output["skipped_invalid"] += 1
            output["results"].append(result)
            print(f"image_sync image={image} status=skipped_invalid_image_ref")
            continue
        if central_has_image(image):
            result["status"] = "skipped_existing"
            output["skipped_existing"] += 1
            output["results"].append(result)
            print(f"image_sync image={image} status=skipped_existing")
            continue

        print(f"image_sync image={image} host={host.get('ip')} status=syncing", flush=True)
        sync_result = sync_image(host, image, args.timeout)
        result.update(sync_result)
        if sync_result["status"] == "synced":
            output["synced"] += 1
        else:
            output["failed"] += 1
        output["results"].append(result)
        print(f"image_sync image={image} status={sync_result['status']}", flush=True)

    if output["failed"]:
        output["status"] = "partial_success" if output["synced"] or output["skipped_existing"] else "failed"
    else:
        output["status"] = "success"

    out = root / "output" / "image-sync" / f"image_sync_{args.run_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")

    if output["status"] == "failed":
        return 2
    if output["status"] == "partial_success":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
