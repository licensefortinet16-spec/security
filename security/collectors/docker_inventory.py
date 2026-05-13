#!/usr/bin/env python3
import argparse
import csv
import json
import os
import shlex
import re
import pwd
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


SSH_IDENTITY_FILE = Path(os.environ.get("SECURITY_SSH_IDENTITY_FILE", "/root/.ssh/id_ed25519"))
SSH_KNOWN_HOSTS_FILE = Path(os.environ.get("SECURITY_SSH_KNOWN_HOSTS_FILE", "/opt/security/security/output/ssh/known_hosts"))


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
    SSH_KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ssh_cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        f"UserKnownHostsFile={SSH_KNOWN_HOSTS_FILE}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        str(SSH_IDENTITY_FILE),
        f"{user}@{ip}",
        command,
    ]
    return subprocess.run(ssh_cmd, text=True, capture_output=True, timeout=timeout)


def run_remote_as_user(host, remote_user, command, timeout=60):
    if not remote_user or remote_user == "root":
        return run_ssh(host, command, timeout=timeout)
    wrapped = f"su -s /bin/bash -c {shlex.quote(command)} {shlex.quote(remote_user)}"
    return run_ssh(host, wrapped, timeout=timeout)


def docker_command(context_name, docker_config=None):
    prefix = "docker"
    if docker_config:
        prefix = f"DOCKER_CONFIG={shlex.quote(docker_config)} docker"
    if not context_name or context_name == "default":
        return prefix
    return f"{prefix} --context {shlex.quote(context_name)}"


def normalize_docker_host(endpoint_host):
    if not endpoint_host:
        return None
    endpoint_host = str(endpoint_host).strip()
    if endpoint_host.startswith("unix:///hostfs/"):
        return "unix:///" + endpoint_host[len("unix:///hostfs/"):]
    if endpoint_host.startswith("unix://hostfs/"):
        return "unix:///" + endpoint_host[len("unix://hostfs/"):]
    return endpoint_host


def raw_docker_host(context):
    return context.get("EndpointHost") or context.get("RawEndpointHost")


def owner_from_endpoint(endpoint_host):
    if not endpoint_host:
        return None
    match = re.search(r"/run/user/(\d+)/", endpoint_host)
    if not match:
        return None
    uid = int(match.group(1))
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def run_docker_context(host, context_name, command, timeout=60, remote_user=None, docker_config=None):
    return run_remote_as_user(
        host,
        remote_user,
        f"{docker_command(context_name, docker_config=docker_config)} {command}",
        timeout=timeout,
    )


def run_docker_host(host, docker_host, command, timeout=60):
    prefix = f"DOCKER_HOST={shlex.quote(docker_host)} docker"
    return run_ssh(host, f"{prefix} {command}", timeout=timeout)


def socket_path_from_endpoint(endpoint_host):
    if not endpoint_host:
        return None
    endpoint_host = str(endpoint_host).strip()
    if endpoint_host.startswith("unix://"):
        path = endpoint_host[len("unix://"):]
        return path if path.startswith("/") else f"/{path}"
    return None


def ensure_context_daemon(host, owner_user, endpoint_host):
    socket_path = socket_path_from_endpoint(endpoint_host)
    if not socket_path:
        return True, None

    check = run_ssh(host, f"test -S {shlex.quote(socket_path)}", timeout=10)
    if check.returncode == 0:
        return True, None
    return False, f"daemon_absent:{socket_path}"


def list_docker_contexts(host):
    result = run_ssh(host, "docker context ls --format '{{json .}}'", timeout=30)
    contexts = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                contexts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if contexts:
        discovered = [{
            "Name": item.get("Name") or "default",
            "Current": bool(item.get("Current")),
            "ContextType": item.get("ContextType") or "moby",
            "Owner": "root",
            "DockerConfig": "/root/.docker",
            "EndpointHost": normalize_docker_host(item.get("DockerEndpoint") or item.get("DockerHost")),
            "RawEndpointHost": item.get("DockerEndpoint") or item.get("DockerHost"),
            "Source": "root",
            "Error": item.get("Error") or "",
        } for item in contexts]
    else:
        discovered = [{"Name": "default", "Current": True, "ContextType": "moby", "Owner": "root", "DockerConfig": "/root/.docker", "EndpointHost": None, "Source": "root"}]

    discovered.extend(discover_user_docker_contexts(host))
    unique = {}
    for item in discovered:
        key = (item.get("Name") or "default", item.get("EndpointHost") or "")
        existing = unique.get(key)
        if not existing:
            unique[key] = item
            continue
        existing_owner = (existing.get("Owner") or "root").strip().lower()
        current_owner = (item.get("Owner") or "root").strip().lower()
        if existing_owner == "root" and current_owner != "root":
            unique[key] = item
    return list(unique.values())


def discover_user_docker_contexts(host):
    command = r"""python3 - <<'PY'
import json
import re
import pwd
from pathlib import Path

seen = []
for entry in pwd.getpwall():
    home = Path(entry.pw_dir or "")
    ctx_root = home / ".docker" / "contexts" / "meta"
    if not ctx_root.exists():
        continue
    for meta_path in ctx_root.glob("*/meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = meta.get("Name") or meta_path.parent.name
        raw_endpoint = ((meta.get("Endpoints") or {}).get("docker") or {}).get("Host")
        endpoint = normalize_docker_host(raw_endpoint)
        if not name:
            continue
        owner = entry.pw_name
        if endpoint:
            match = re.search(r"/run/user/(\d+)/", endpoint)
            if match:
                try:
                    owner = pwd.getpwuid(int(match.group(1))).pw_name
                except KeyError:
                    pass
        seen.append({
            "Name": name,
            "Current": False,
            "ContextType": meta.get("ContextType") or "moby",
            "Owner": owner,
            "DockerConfig": str(home / ".docker"),
            "EndpointHost": endpoint,
            "RawEndpointHost": raw_endpoint,
            "Source": str(meta_path),
            "Error": "",
        })
print(json.dumps(seen))
PY"""
    result = run_ssh(host, command, timeout=30)
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "unknown"


def collect_host(host, context_aliases):
    result = {
        "host": host,
        "status": "unknown",
        "collected_at": utc_now(),
        "errors": [],
        "docker_version": None,
        "contexts": [],
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
    remote_hostname = probe_lines[0] if probe_lines else None
    if remote_hostname:
        host = dict(host)
        host["configured_name"] = host.get("name")
        host["name"] = remote_hostname
        result["host"] = host
    result["remote_hostname"] = remote_hostname
    result["docker_version"] = probe_lines[-1] if probe_lines else None

    contexts = list_docker_contexts(host)
    containers = []
    images = []
    findings = []
    context_results = []
    for context in contexts:
        context_name = context.get("Name") or "default"
        context_error = context.get("Error") or ""
        endpoint_host = normalize_docker_host(context.get("EndpointHost"))
        owner_user = owner_from_endpoint(endpoint_host) or context.get("Owner") or "root"
        docker_config = context.get("DockerConfig")
        docker_prefix = docker_command(context_name, docker_config=docker_config) if not endpoint_host else f"DOCKER_HOST={shlex.quote(endpoint_host)} docker"
        context_result = {
            "name": context_name,
            "description": context.get("Description"),
            "current": bool(context.get("Current")),
            "type": context.get("ContextType"),
            "owner_user": owner_user,
            "docker_config": docker_config,
            "endpoint_host": endpoint_host,
            "raw_endpoint_host": raw_docker_host(context),
            "source": context.get("Source"),
            "status": "unknown",
            "containers": 0,
            "images": 0,
            "errors": [],
        }

        if context_error:
            context_result["status"] = "context_unavailable"
            context_result["errors"].append({
                "stage": "docker_context_preflight",
                "returncode": 1,
                "stderr": sanitize(context_error),
            })
            context_results.append(context_result)
            result["errors"].extend(context_result["errors"])
            continue

        if endpoint_host:
            ready, ready_error = ensure_context_daemon(host, owner_user, endpoint_host)
            if not ready:
                context_result["status"] = "daemon_absent"
                context_result["errors"].append({
                    "stage": "docker_daemon_preflight",
                    "returncode": 1,
                    "stderr": ready_error,
                })
                context_results.append(context_result)
                continue

        if endpoint_host:
            ps_command = f"DOCKER_HOST={shlex.quote(endpoint_host)} docker ps -a --no-trunc --format '{{{{json .}}}}'"
            ps = run_remote_as_user(host, owner_user, ps_command, timeout=60)
        else:
            ps = run_docker_context(host, context_name, "ps -a --no-trunc --format '{{json .}}'", timeout=60, remote_user=owner_user, docker_config=docker_config)
        if ps.returncode != 0:
            context_result["status"] = "inventory_failed"
            context_result["errors"].append({
                "stage": "docker_ps",
                "returncode": ps.returncode,
                "stderr": sanitize(ps.stderr),
            })
            context_results.append(context_result)
            result["errors"].extend(context_result["errors"])
            continue

        ps_rows = []
        for line in ps.stdout.splitlines():
            if not line.strip():
                continue
            try:
                ps_rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                context_result["errors"].append({"stage": "docker_ps_parse", "error": str(exc), "line": line[:200]})

        inspect_command = f"ids=$({docker_prefix} ps -aq); if [ -n \"$ids\" ]; then {docker_prefix} inspect $ids; else printf '[]'; fi"
        inspected = run_remote_as_user(host, owner_user, inspect_command, timeout=120)
        if inspected.returncode != 0:
            context_result["status"] = "inventory_failed"
            context_result["errors"].append({
                "stage": "docker_inspect",
                "returncode": inspected.returncode,
                "stderr": sanitize(inspected.stderr),
            })
            context_results.append(context_result)
            result["errors"].extend(context_result["errors"])
            continue

        try:
            inspect_rows = json.loads(inspected.stdout or "[]")
        except json.JSONDecodeError as exc:
            context_result["status"] = "inventory_failed"
            context_result["errors"].append({"stage": "docker_inspect_parse", "error": str(exc)})
            context_results.append(context_result)
            result["errors"].extend(context_result["errors"])
            continue

        image_command = f"{docker_prefix} images --digests --no-trunc --format '{{{{json .}}}}'"
        image_rows = []
        image_result = run_remote_as_user(host, owner_user, image_command, timeout=60)
        if image_result.returncode == 0:
            for line in image_result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    image_rows.append(json.loads(line))
                except json.JSONDecodeError:
                    context_result["errors"].append({"stage": "docker_images_parse", "line": line[:200]})
        else:
            context_result["errors"].append({
                "stage": "docker_images",
                "returncode": image_result.returncode,
                "stderr": sanitize(image_result.stderr),
            })

        ps_by_id = {row.get("ID", "")[:12]: row for row in ps_rows}
        context_containers = []
        context_findings = []
        for item in inspect_rows:
            container = normalize_container(
                host,
                item,
                ps_by_id,
                context_aliases,
                collection_context=context_name,
                collection_owner=owner_user,
                collection_endpoint_host=endpoint_host,
            )
            context_containers.append(container)
            context_findings.extend(check_container(host, item, container))

        containers.extend(context_containers)
        findings.extend(context_findings)
        images.extend(
            normalize_images(
                host,
                image_rows,
                context_containers,
                collection_context=context_name,
                collection_owner=owner_user,
                collection_endpoint_host=endpoint_host,
            )
        )
        context_result["status"] = "success"
        context_result["containers"] = len(context_containers)
        context_result["images"] = len(image_rows)
        context_results.append(context_result)

    result["contexts"] = context_results
    result["contexts_total"] = len(context_results)
    result["contexts_success"] = sum(1 for item in context_results if item.get("status") == "success")
    result["containers"] = containers
    result["images"] = images
    result["findings"] = findings
    if context_results and all(item.get("status") == "success" for item in context_results):
        result["status"] = "success"
    elif any(item.get("status") == "success" for item in context_results):
        result["status"] = "partial_success"
    else:
        result["status"] = "scan_failed"
    return result


def normalize_container(host, item, ps_by_id, aliases=None, collection_context=None, collection_owner=None, collection_endpoint_host=None):
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
        "context": resolve_context(host, labels, aliases, collection_context=collection_context),
        "context_source": resolve_context_source(host, labels, collection_context=collection_context),
        "docker_context": collection_context or "default",
        "docker_context_owner": collection_owner or "root",
        "docker_endpoint_host": collection_endpoint_host,
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


def resolve_context_source(host, labels, collection_context=None):
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
    if collection_context:
        return f"docker.context:{collection_context}"
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


def resolve_context(host, labels, aliases=None, collection_context=None):
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
    if collection_context:
        normalized = normalize_context_value(collection_context)
        for canonical, values in aliases.items():
            if normalized == canonical or normalized in values:
                return canonical
        if "openpanel" in normalized:
            return "openpanel"
        return normalized or "docker default"
    if host.get("openpanel"):
        return "openpanel"
    return "docker default"


def normalize_images(host, image_rows, containers, collection_context=None, collection_owner=None, collection_endpoint_host=None):
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
            "context": collection_context or "default",
            "docker_context": collection_context or "default",
            "docker_context_owner": collection_owner or "root",
            "docker_endpoint_host": collection_endpoint_host,
        })
    return rows


def check_container(host, raw, container):
    findings = []
    base = {
        "host_name": host.get("name"),
        "host_ip": host.get("ip"),
        "context": container.get("context"),
        "context_source": container.get("context_source"),
        "docker_context": container.get("docker_context"),
        "docker_context_owner": container.get("docker_context_owner"),
        "docker_endpoint_host": container.get("docker_endpoint_host"),
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
    fields = ["host_name", "host_ip", "context", "context_source", "docker_context", "docker_context_owner", "short_id", "name", "image", "status", "running", "network_mode", "pid_mode", "privileged", "user", "has_healthcheck"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def write_findings_csv(path, rows):
    fields = ["host_name", "host_ip", "context", "context_source", "docker_context", "docker_context_owner", "container_id", "container_name", "image", "type", "severity", "evidence", "recommendation"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def main():
    parser = argparse.ArgumentParser(description="Collect Docker inventory from remote hosts through SSH.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security/security"))
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
        print(f"collecting host_ip={host.get('ip')}", flush=True)
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
            "hosts_success": sum(1 for r in all_results if r.get("status") in {"success", "partial_success"}),
            "contexts_total": sum(r.get("contexts_total", 0) for r in all_results),
            "contexts_success": sum(r.get("contexts_success", 0) for r in all_results),
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
    success = sum(1 for r in results if r.get("status") in {"success", "partial_success"})
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
