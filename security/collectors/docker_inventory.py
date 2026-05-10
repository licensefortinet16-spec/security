#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import tomllib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SENSITIVE_MOUNTS = (
    "/var/run/docker.sock",
    "/etc",
    "/root",
    "/var/lib/docker",
    "/proc",
    "/sys",
)

DANGEROUS_CAPS = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "ALL",
}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_hosts(path):
    hosts = []
    current = None
    if not path.exists():
      raise FileNotFoundError(f"hosts config not found: {path}")

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped == "hosts:":
            continue
        if stripped.startswith("- "):
            if current:
                hosts.append(current)
            current = {}
            item = stripped[2:].strip()
            if item:
                key, value = parse_key_value(item)
                current[key] = value
            continue
        if current is not None and ":" in stripped:
            key, value = parse_key_value(stripped)
            current[key] = value
    if current:
        hosts.append(current)
    return hosts


def parse_key_value(item):
    key, value = item.split(":", 1)
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    elif value.lower() == "true":
        value = True
    elif value.lower() == "false":
        value = False
    return key.strip(), value


def run_ssh(host, command, timeout=60):
    user = host.get("ssh_user", "root")
    ip = host["ip"]
    ssh_cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{user}@{ip}",
        command,
    ]
    return subprocess.run(ssh_cmd, text=True, capture_output=True, timeout=timeout)


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "unknown"


def collect_host(host, context_aliases):
    result = {
        "host": host,
        "status": "unknown",
        "collected_at": utc_now(),
        "errors": [],
        "docker_version": None,
        "containers": [],
        "images": [],
        "findings": [],
    }

    probe = run_ssh(host, "hostname; command -v docker; docker --version", timeout=20)
    if probe.returncode != 0:
        result["status"] = "scan_failed"
        result["errors"].append({
            "stage": "ssh_or_docker_probe",
            "returncode": probe.returncode,
            "stderr": sanitize(probe.stderr),
        })
        return result

    probe_lines = [line for line in probe.stdout.splitlines() if line.strip()]
    result["remote_hostname"] = probe_lines[0] if probe_lines else None
    result["docker_version"] = probe_lines[-1] if probe_lines else None

    ps_command = "docker ps -a --no-trunc --format '{{json .}}'"
    ps = run_ssh(host, ps_command, timeout=60)
    if ps.returncode != 0:
        result["status"] = "inventory_failed"
        result["errors"].append({
            "stage": "docker_ps",
            "returncode": ps.returncode,
            "stderr": sanitize(ps.stderr),
        })
        return result

    ps_rows = []
    for line in ps.stdout.splitlines():
        if not line.strip():
            continue
        try:
            ps_rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            result["errors"].append({"stage": "docker_ps_parse", "error": str(exc), "line": line[:200]})

    inspect_command = "ids=$(docker ps -aq); if [ -n \"$ids\" ]; then docker inspect $ids; else printf '[]'; fi"
    inspected = run_ssh(host, inspect_command, timeout=120)
    if inspected.returncode != 0:
        result["status"] = "inventory_failed"
        result["errors"].append({
            "stage": "docker_inspect",
            "returncode": inspected.returncode,
            "stderr": sanitize(inspected.stderr),
        })
        return result

    try:
        inspect_rows = json.loads(inspected.stdout or "[]")
    except json.JSONDecodeError as exc:
        result["status"] = "inventory_failed"
        result["errors"].append({"stage": "docker_inspect_parse", "error": str(exc)})
        return result

    image_command = "docker images --digests --no-trunc --format '{{json .}}'"
    image_rows = []
    images = run_ssh(host, image_command, timeout=60)
    if images.returncode == 0:
        for line in images.stdout.splitlines():
            if not line.strip():
                continue
            try:
                image_rows.append(json.loads(line))
            except json.JSONDecodeError:
                result["errors"].append({"stage": "docker_images_parse", "line": line[:200]})
    else:
        result["errors"].append({
            "stage": "docker_images",
            "returncode": images.returncode,
            "stderr": sanitize(images.stderr),
        })

    ps_by_id = {row.get("ID", "")[:12]: row for row in ps_rows}
    containers = []
    findings = []
    for item in inspect_rows:
        container = normalize_container(host, item, ps_by_id, context_aliases)
        containers.append(container)
        findings.extend(check_container(host, item, container))

    result["containers"] = containers
    result["images"] = normalize_images(host, image_rows, containers)
    result["findings"] = findings
    result["status"] = "success"
    return result


def normalize_container(host, item, ps_by_id, aliases=None):
    cid = item.get("Id", "")
    config = item.get("Config") or {}
    host_config = item.get("HostConfig") or {}
    network_settings = item.get("NetworkSettings") or {}
    state = item.get("State") or {}
    ps_row = ps_by_id.get(cid[:12], {})
    ports = network_settings.get("Ports") or {}
    labels = config.get("Labels") or {}

    return {
        "host_name": host.get("name"),
        "host_ip": host.get("ip"),
        "id": cid,
        "short_id": cid[:12],
        "name": (item.get("Name") or "").lstrip("/"),
        "image": config.get("Image") or ps_row.get("Image"),
        "image_id": item.get("Image"),
        "status": state.get("Status") or ps_row.get("State"),
        "running": bool(state.get("Running")),
        "created": item.get("Created"),
        "command": " ".join(config.get("Cmd") or []) if isinstance(config.get("Cmd"), list) else config.get("Cmd"),
        "entrypoint": config.get("Entrypoint"),
        "user": config.get("User") or "",
        "labels": labels,
        "context": resolve_context(host, labels, aliases),
        "context_source": resolve_context_source(host, labels),
        "ports": ports,
        "mounts": item.get("Mounts") or [],
        "binds": host_config.get("Binds") or [],
        "networks": list((network_settings.get("Networks") or {}).keys()),
        "network_mode": host_config.get("NetworkMode"),
        "pid_mode": host_config.get("PidMode"),
        "privileged": bool(host_config.get("Privileged")),
        "cap_add": host_config.get("CapAdd") or [],
        "cap_drop": host_config.get("CapDrop") or [],
        "memory_limit": host_config.get("Memory"),
        "nano_cpus": host_config.get("NanoCpus"),
        "cpu_shares": host_config.get("CpuShares"),
        "has_healthcheck": bool(config.get("Healthcheck")),
    }


def resolve_context_source(host, labels):
    candidates = (
        "com.docker.compose.project",
        "io.docker.compose.project",
        "com.openpanel.context",
        "openpanel.context",
        "app.openpanel.context",
        "context",
    )
    for key in candidates:
        value = labels.get(key)
        if value:
            return key
    if host.get("openpanel"):
        return "host.openpanel"
    return "default"


def load_context_aliases(root):
    policy_path = root / "config" / "context_aliases.toml"
    if not policy_path.exists():
        return {
            "openpanel": {"openpanel", "openpanel-default", "openpanel-stack"},
            "docker default": {"default", "docker default", "standalone", "compose-default"},
        }
    data = tomllib.loads(policy_path.read_text(encoding="utf-8"))
    aliases = {}
    for canonical, values in (data.get("aliases") or {}).items():
        aliases[str(canonical).strip().lower()] = {str(value).strip().lower() for value in values or [] if str(value).strip()}
    return aliases


def normalize_context_value(value):
    text = str(value or "").strip().lower().replace("_", "-")
    text = re.sub(r"\s+", " ", text)
    return text


def resolve_context(host, labels, aliases=None):
    aliases = aliases or {}
    candidates = (
        "com.openpanel.context",
        "openpanel.context",
        "app.openpanel.context",
        "context",
        "com.docker.compose.project",
        "io.docker.compose.project",
    )
    for key in candidates:
        value = labels.get(key)
        if value:
            normalized = normalize_context_value(value)
            for canonical, values in aliases.items():
                if normalized == canonical or normalized in values:
                    return canonical
            if "openpanel" in normalized:
                return "openpanel"
            return normalized or "docker default"
    if host.get("openpanel"):
        return "openpanel"
    return "docker default"


def normalize_images(host, image_rows, containers):
    used = {c.get("image") for c in containers if c.get("image")}
    rows = []
    for row in image_rows:
        repository = row.get("Repository")
        tag = row.get("Tag")
        ref = repository if tag in ("", "<none>", None) else f"{repository}:{tag}"
        rows.append({
            "host_name": host.get("name"),
            "host_ip": host.get("ip"),
            "repository": repository,
            "tag": tag,
            "digest": row.get("Digest"),
            "image_id": row.get("ID"),
            "created_since": row.get("CreatedSince"),
            "created_at": row.get("CreatedAt"),
            "size": row.get("Size"),
            "reference": ref,
            "used_by_containers": ref in used,
        })
    return rows


def check_container(host, raw, container):
    findings = []
    base = {
        "host_name": host.get("name"),
        "host_ip": host.get("ip"),
        "container_id": container.get("short_id"),
        "container_name": container.get("name"),
        "image": container.get("image"),
    }

    def add(kind, severity, evidence, recommendation):
        item = dict(base)
        item.update({
            "type": kind,
            "severity": severity,
            "evidence": evidence,
            "recommendation": recommendation,
        })
        findings.append(item)

    if container.get("privileged"):
        add("privileged_container", "critical", "HostConfig.Privileged=true", "Remover modo privileged e conceder apenas capabilities estritamente necessarias.")

    if container.get("network_mode") == "host":
        add("host_network_mode", "high", "HostConfig.NetworkMode=host", "Evitar network host; publicar apenas portas necessarias.")

    if container.get("pid_mode") == "host":
        add("host_pid_mode", "high", "HostConfig.PidMode=host", "Evitar compartilhamento de PID namespace com o host.")

    mounts = container.get("mounts") or []
    binds = container.get("binds") or []
    mount_sources = [m.get("Source", "") for m in mounts if isinstance(m, dict)] + [b.split(":", 1)[0] for b in binds if isinstance(b, str)]
    for source in mount_sources:
        for sensitive in SENSITIVE_MOUNTS:
            if source == sensitive or source.startswith(f"{sensitive}/"):
                severity = "critical" if sensitive == "/var/run/docker.sock" else "high"
                kind = "docker_socket_mounted" if sensitive == "/var/run/docker.sock" else "sensitive_host_path_mounted"
                add(kind, severity, f"mount_source={source}", "Remover montagem sensivel ou substituir por volume com escopo minimo.")
                break

    user = (container.get("user") or "").strip()
    if user in ("", "0", "root"):
        add("running_as_root", "medium", f"Config.User={user or '<empty>'}", "Definir usuario nao-root na imagem ou no compose.")

    if not container.get("has_healthcheck"):
        add("missing_healthcheck", "low", "Config.Healthcheck absent", "Adicionar healthcheck para reduzir tempo de deteccao de falhas.")

    image = container.get("image") or ""
    if image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]:
        add("latest_tag", "medium", f"image={image}", "Fixar tag imutavel ou digest da imagem.")

    cap_add = set(container.get("cap_add") or [])
    risky_caps = sorted(cap_add.intersection(DANGEROUS_CAPS))
    if risky_caps:
        add("dangerous_capability", "high", f"cap_add={','.join(risky_caps)}", "Remover capabilities perigosas e usar principio do menor privilegio.")

    if has_public_port(container.get("ports") or {}):
        add("public_port_exposed", "medium", "published_port bound to 0.0.0.0, :: or wildcard", "Restringir bind de portas ao IP necessario ou proteger por firewall/reverse proxy.")

    if not container.get("memory_limit"):
        add("missing_memory_limit", "low", "HostConfig.Memory=0", "Definir limite de memoria para reduzir impacto operacional.")

    if not container.get("nano_cpus") and not container.get("cpu_shares"):
        add("missing_cpu_limit", "low", "HostConfig.NanoCpus=0 and CpuShares=0", "Definir limite ou shares de CPU conforme criticidade.")

    return findings


def has_public_port(ports):
    for bindings in ports.values():
        if not bindings:
            continue
        for binding in bindings:
            host_ip = (binding or {}).get("HostIp", "")
            if host_ip in ("", "0.0.0.0", "::"):
                return True
    return False


def sanitize(value):
    text = value or ""
    text = re.sub(r"(?i)(api[_-]?key|token|password|secret)=\S+", r"\1=<redacted>", text)
    return text[-4000:]


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_containers_csv(path, rows):
    fields = ["host_name", "host_ip", "short_id", "name", "image", "status", "running", "network_mode", "pid_mode", "privileged", "user", "has_healthcheck"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def write_findings_csv(path, rows):
    fields = ["host_name", "host_ip", "container_id", "container_name", "image", "type", "severity", "evidence", "recommendation"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def main():
    parser = argparse.ArgumentParser(description="Collect Docker inventory from remote hosts through SSH.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()

    root = Path(args.root)
    context_aliases = load_context_aliases(root)
    hosts = load_hosts(root / "config" / "hosts.yml")
    if not hosts:
        print("no hosts configured", file=sys.stderr)
        return 2

    all_results = []
    all_containers = []
    all_findings = []
    for host in hosts:
        print(f"collecting host={host.get('name')} ip={host.get('ip')}", flush=True)
        result = collect_host(host, context_aliases)
        all_results.append(result)
        all_containers.extend(result.get("containers", []))
        all_findings.extend(result.get("findings", []))

    output = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "status": summarize_status(all_results),
        "hosts": all_results,
        "summary": {
            "hosts_total": len(all_results),
            "hosts_success": sum(1 for r in all_results if r.get("status") == "success"),
            "containers_total": len(all_containers),
            "images_total": len({c.get("image") for c in all_containers if c.get("image")}),
            "findings_total": len(all_findings),
            "findings_by_severity": count_by(all_findings, "severity"),
            "findings_by_type": count_by(all_findings, "type"),
        },
    }

    inventory_dir = root / "output" / "inventory"
    reports_dir = root / "output" / "reports"
    history_dir = root / "output" / "history"

    write_json(inventory_dir / f"inventory_{args.run_id}.json", output)
    write_json(reports_dir / f"findings_{args.run_id}.json", all_findings)
    write_json(history_dir / f"scan_summary_{args.run_id}.json", output["summary"])
    write_containers_csv(inventory_dir / f"containers_{args.run_id}.csv", all_containers)
    write_findings_csv(reports_dir / f"findings_{args.run_id}.csv", all_findings)

    if output["status"] == "failed":
        return 2
    if output["status"] == "partial_success":
        return 1
    return 0


def summarize_status(results):
    if not results:
        return "failed"
    success = sum(1 for r in results if r.get("status") == "success")
    if success == len(results):
        return "success"
    if success > 0:
        return "partial_success"
    return "failed"


def count_by(rows, field):
    counts = {}
    for row in rows:
        value = row.get(field) or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return counts


if __name__ == "__main__":
    sys.exit(main())
