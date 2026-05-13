#!/usr/bin/env python3
import argparse
import json
import mimetypes
import os
import re
import ssl
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request


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
            value = value.strip().strip('"').strip("'")
            values[key.strip()] = value
    values.update({key: value for key, value in os.environ.items() if key.startswith("DTRACK_")})
    return values


def latest_summary(root, run_id):
    exact = root / "output" / "trivy" / f"trivy_summary_{run_id}.json"
    if exact.exists():
        return exact
    candidates = sorted((root / "output" / "trivy").glob("trivy_summary_*.json"))
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


def multipart(fields, files):
    boundary = f"----security-monitor-{uuid.uuid4().hex}"
    body = bytearray()
    for key, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        body.extend(str(value).encode())
        body.extend(b"\r\n")
    for key, path in files.items():
        path = Path(path)
        content_type = mimetypes.guess_type(path.name)[0] or "application/json"
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{key}"; filename="{path.name}"\r\n'.encode())
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode())
        body.extend(path.read_bytes())
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def post_bom(dtrack_url, api_key, image, sbom_path, timeout, insecure_tls):
    sbom_path = sanitize_cyclonedx_sbom(sbom_path)
    project_name, project_version = split_image_ref(image)
    url = dtrack_url.rstrip("/") + "/api/v1/bom"
    fields = {
        "autoCreate": "true",
        "projectName": project_name,
        "projectVersion": project_version,
    }
    body, content_type = multipart(fields, {"bom": sbom_path})
    req = request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "X-Api-Key": api_key,
            "Content-Type": content_type,
            "Accept": "application/json",
            "User-Agent": "container-security-monitor/0.1",
        },
    )
    context = ssl._create_unverified_context() if insecure_tls else None
    with request.urlopen(req, timeout=timeout, context=context) as response:
        payload = response.read().decode("utf-8", errors="replace")
        return response.status, payload


def sanitize_cyclonedx_sbom(sbom_path):
    path = Path(sbom_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return path

    changed = False
    for dependency in data.get("dependencies", []) or []:
        depends_on = dependency.get("dependsOn")
        if not isinstance(depends_on, list):
            continue
        deduped = list(dict.fromkeys(depends_on))
        if deduped != depends_on:
            dependency["dependsOn"] = deduped
            changed = True

    if not changed:
        return path

    sanitized_dir = path.parent / "sanitized"
    sanitized_dir.mkdir(parents=True, exist_ok=True)
    sanitized_path = sanitized_dir / path.name
    sanitized_path.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    return sanitized_path


def sanitize_error(value):
    text = str(value or "")
    text = re.sub(r"(?i)(x-api-key:?\s*)\S+", r"\1<redacted>", text)
    text = re.sub(r"(?i)(api[_-]?key|token|password|secret)=\S+", r"\1=<redacted>", text)
    return text[-4000:]


def main():
    parser = argparse.ArgumentParser(description="Upload CycloneDX SBOMs to Dependency-Track.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    root = Path(args.root)
    env_path = root / "config" / "dependency-track.env"
    config = load_env(env_path)
    dtrack_url = config.get("DTRACK_URL", "").strip()
    api_key = config.get("DTRACK_API_KEY", "").strip()
    insecure_tls = config.get("DTRACK_INSECURE_TLS", "false").lower() == "true"

    summary = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "status": "unknown",
        "configured": bool(dtrack_url and api_key),
        "uploaded": 0,
        "failed": 0,
        "skipped": 0,
        "results": [],
    }

    output_path = root / "output" / "dtrack" / f"dtrack_upload_{args.run_id}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not dtrack_url or not api_key:
        summary["status"] = "skipped_not_configured"
        output_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        print("Dependency-Track not configured; skipping SBOM upload")
        return 0

    trivy_summary_path = latest_summary(root, args.run_id)
    if not trivy_summary_path:
        summary["status"] = "skipped_no_trivy_summary"
        output_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        print("Trivy summary not found; skipping SBOM upload", file=sys.stderr)
        return 1

    trivy_summary = json.loads(trivy_summary_path.read_text(encoding="utf-8"))
    for item in trivy_summary.get("results", []):
        image = item.get("image")
        sbom_path = item.get("sbom_output")
        if item.get("status") != "success" or not sbom_path or not Path(sbom_path).exists():
            summary["skipped"] += 1
            summary["results"].append({
                "image": image,
                "status": "skipped_no_sbom",
            })
            continue
        try:
            status_code, payload = post_bom(dtrack_url, api_key, image, sbom_path, args.timeout, insecure_tls)
            summary["uploaded"] += 1
            summary["results"].append({
                "image": image,
                "status": "uploaded",
                "http_status": status_code,
                "response": payload[:1000],
            })
            print(f"dtrack_upload image={image} status=uploaded")
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            summary["failed"] += 1
            summary["results"].append({
                "image": image,
                "status": "upload_failed",
                "http_status": exc.code,
                "error": sanitize_error(body or exc),
            })
            print(f"dtrack_upload image={image} status=upload_failed http={exc.code}", file=sys.stderr)
        except Exception as exc:
            summary["failed"] += 1
            summary["results"].append({
                "image": image,
                "status": "upload_failed",
                "error": sanitize_error(exc),
            })
            print(f"dtrack_upload image={image} status=upload_failed", file=sys.stderr)

    if summary["failed"]:
        summary["status"] = "partial_success" if summary["uploaded"] else "failed"
    else:
        summary["status"] = "success"

    output_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
