#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path


SSH_IDENTITY_FILE = Path(os.environ.get("SECURITY_SSH_IDENTITY_FILE", "/root/.ssh/id_ed25519"))
SSH_KNOWN_HOSTS_FILE = Path(os.environ.get("SECURITY_SSH_KNOWN_HOSTS_FILE", "/opt/security/security/output/ssh/known_hosts"))


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("_") or "unknown"


def latest_inventory(root, run_id):
    exact = root / "output" / "inventory" / f"inventory_{run_id}.json"
    if exact.exists():
        return exact
    candidates = sorted((root / "output" / "inventory").glob("inventory_*.json"))
    return candidates[-1] if candidates else None


def ssh_base(host):
    user = host.get("ssh_user", "root")
    ip = host["ip"]
    SSH_KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    return [
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
    ]


def code_targets(inventory):
    rows = []
    seen = set()
    for host_result in inventory.get("hosts", []) or []:
        if host_result.get("status") not in {"success", "partial_success"}:
            continue
        host = host_result.get("host") or {}
        for context in host_result.get("contexts", []) or []:
            name = context.get("name")
            if not name or name == "default":
                continue
            key = (host.get("ip"), name)
            if key in seen:
                continue
            seen.add(key)
            remote_root = f"/home/{name}"
            rows.append({
                "host": host,
                "host_name": host_result.get("remote_hostname") or host.get("name"),
                "client": name,
                "remote_path": remote_root,
                "scan_path": remote_root,
            })
    return rows


def remote_path_exists(target):
    return remote_dir_exists(target["host"], target["scan_path"])


def remote_dir_exists(host, path):
    cmd = ssh_base(host) + ["test", "-d", path]
    return subprocess.run(cmd, text=True, capture_output=True, timeout=30).returncode == 0


def choose_scan_path(target):
    files_path = f"{target['remote_path']}/files"
    if remote_dir_exists(target["host"], files_path):
        return files_path
    return target["remote_path"]


def copy_remote_code(target, destination, timeout):
    destination.mkdir(parents=True, exist_ok=True)
    scan_path = target["scan_path"].rstrip("/")
    parent = str(Path(scan_path).parent)
    leaf = Path(scan_path).name
    tar_cmd = (
        "tar -h "
        "--exclude=.git --exclude=node_modules --exclude=vendor --exclude=.cache "
        "--exclude=tmp --exclude=logs --exclude=log --exclude=backup --exclude=backups "
        "--exclude='*.sql' --exclude='*.tar' --exclude='*.tar.gz' --exclude='*.zip' "
        f"-C {sh_quote(parent)} -cf - {sh_quote(leaf)}"
    )
    ssh_proc = subprocess.Popen(
        ssh_base(target["host"]) + [tar_cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    tar_proc = subprocess.Popen(
        ["tar", "-xf", "-", "-C", str(destination)],
        stdin=ssh_proc.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if ssh_proc.stdout:
        ssh_proc.stdout.close()
    try:
        _, tar_stderr = tar_proc.communicate(timeout=timeout)
        ssh_stderr = ssh_proc.stderr.read() if ssh_proc.stderr else b""
        ssh_return = ssh_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        ssh_proc.kill()
        tar_proc.kill()
        return {
            "status": "copy_failed_timeout",
            "stderr": "copy timed out",
        }
    if ssh_return != 0 or tar_proc.returncode != 0:
        return {
            "status": "copy_failed",
            "ssh_returncode": ssh_return,
            "tar_returncode": tar_proc.returncode,
            "stderr": sanitize((ssh_stderr + tar_stderr).decode("utf-8", errors="replace")),
        }
    return {"status": "copied", "local_path": str(destination / leaf)}


def sh_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def run_trivy_code(root, run_id, target, local_path, timeout):
    out_dir = root / "output" / "code"
    cache_dir = root / ".cache" / "trivy"
    tmp_dir = root / "tmp" / "trivy-code"
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    base = safe_name(f"{target.get('host_name')}_{target['client']}")
    output_path = out_dir / f"trivy_code_{base}_{run_id}.json"
    cmd = [
        "trivy",
        "fs",
        "--quiet",
        "--cache-dir",
        str(cache_dir),
        "--scanners",
        "secret,misconfig",
        "--skip-dirs",
        ".git,node_modules,vendor,.cache,tmp,logs,log,backup,backups",
        "--format",
        "json",
        "--output",
        str(output_path),
        str(local_path),
    ]
    env = os.environ.copy()
    env["TMPDIR"] = str(tmp_dir)
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, env=env)
    if result.returncode != 0:
        return {
            "status": "scan_failed",
            "output": str(output_path),
            "stderr": sanitize(result.stderr),
        }
    redact_secret_evidence(output_path)
    summary = summarize_trivy_output(output_path, Path(local_path), target["scan_path"])
    semgrep_status = merge_source_findings(
        summary,
        scan_source_findings(root, Path(local_path), target["scan_path"], target["client"], timeout),
    )
    allowlist = load_code_allowlist(root)
    severity_policy = load_code_severity_policy(root)
    apply_code_policy(summary, target["client"], allowlist, severity_policy)
    return {
        "status": "success",
        "output": str(output_path),
        "semgrep_status": semgrep_status,
        **summary,
    }


def redact_secret_evidence(path):
    output_path = Path(path)
    data = json.loads(output_path.read_text(encoding="utf-8"))
    changed = False
    for result in data.get("Results", []) or []:
        for secret in result.get("Secrets", []) or []:
            for key in ("Code", "Match"):
                if key in secret:
                    secret[key] = "<redacted>"
                    changed = True
    if changed:
        output_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def summarize_trivy_output(path, local_root, remote_scan_path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    severity_counts = {}
    vulnerabilities = 0
    secrets = 0
    misconfigurations = 0
    top = []
    for result in data.get("Results", []) or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity") or "UNKNOWN"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            vulnerabilities += 1
            if len(top) < 100:
                top.append({
                    "type": "vulnerability",
                    "target": display_scan_target(target, local_root, remote_scan_path),
                    "id": vuln.get("VulnerabilityID"),
                    "severity": severity,
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "title": vuln.get("Title") or (vuln.get("Description") or "")[:160],
                    "remediation": vulnerability_remediation(vuln),
                })
        for secret in result.get("Secrets", []) or []:
            severity = secret.get("Severity") or "UNKNOWN"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            secrets += 1
            if len(top) < 100:
                top.append({
                    "type": "secret",
                    "target": display_scan_target(target, local_root, remote_scan_path),
                    "id": secret.get("RuleID"),
                    "severity": severity,
                    "package": "",
                    "installed_version": "",
                    "fixed_version": "",
                    "title": secret.get("Title") or "Potential secret detected",
                    "remediation": secret_remediation(secret),
                })
        for misconfig in result.get("Misconfigurations", []) or []:
            severity = misconfig.get("Severity") or "UNKNOWN"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            misconfigurations += 1
            if len(top) < 100:
                top.append({
                    "type": "misconfiguration",
                    "target": display_scan_target(target, local_root, remote_scan_path),
                    "id": misconfig.get("ID"),
                    "severity": severity,
                    "package": misconfig.get("Type") or "",
                    "installed_version": "",
                    "fixed_version": "",
                    "title": misconfig.get("Title") or misconfig.get("Message") or "",
                    "remediation": misconfiguration_remediation(misconfig),
                })
    return {
        "vulnerabilities": vulnerabilities,
        "secrets": secrets,
        "misconfigurations": misconfigurations,
        "code_findings": 0,
        "suppressed_findings": 0,
        "severity_counts": severity_counts,
        "top_findings": top,
    }


def merge_source_findings(summary, findings):
    semgrep_status = "not_run"
    if isinstance(findings, dict):
        semgrep_status = findings.get("semgrep_status", "not_run")
        findings = findings.get("findings", [])
    summary["code_findings"] = int(summary.get("code_findings") or 0) + len(findings)
    for finding in findings:
        severity = finding.get("severity") or "UNKNOWN"
        counts = summary.setdefault("severity_counts", {})
        counts[severity] = counts.get(severity, 0) + 1
        if len(summary.setdefault("top_findings", [])) < 100:
            summary["top_findings"].append(finding)
    return semgrep_status


def scan_source_findings(root, local_path, remote_scan_path, client, timeout):
    findings = []
    semgrep = run_semgrep(root, local_path, remote_scan_path, client, timeout)
    findings.extend(semgrep.get("findings", []))
    if not semgrep.get("findings"):
        semgrep["fallback_used"] = True
        semgrep["findings"] = []
    else:
        semgrep["fallback_used"] = False
    for path in sorted(local_path.rglob("*.php")):
        if is_ignored_source_path(path, local_path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fallback = scan_php_lfi(path, local_path, remote_scan_path, text)
        existing = {(item.get("type"), item.get("target")) for item in findings}
        findings.extend(item for item in fallback if (item.get("type"), item.get("target")) not in existing)
    semgrep["findings"] = findings
    return semgrep


def run_semgrep(root, local_path, remote_scan_path, client, timeout):
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return {"semgrep_status": "not_installed", "findings": []}
    rules = root / "config" / "semgrep-rules.yml"
    if not rules.exists():
        return {"semgrep_status": "rules_missing", "findings": []}
    output_path = root / "output" / "code" / f"semgrep_{safe_name(client)}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    cmd = [
        semgrep_bin,
        "--config",
        str(rules),
        "--json",
        "--metrics=off",
        "--no-git-ignore",
        str(local_path),
    ]
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    output_path.write_text(result.stdout or "{}", encoding="utf-8")
    if result.returncode not in (0, 1):
        return {"semgrep_status": "failed", "stderr": sanitize(result.stderr), "findings": []}
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {"semgrep_status": "invalid_json", "stderr": sanitize(result.stderr), "findings": []}
    findings = []
    for item in data.get("results", []) or []:
        path = Path(item.get("path") or "")
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        severity = (extra.get("severity") or metadata.get("impact") or "WARNING").upper()
        severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(severity, severity)
        findings.append({
            "type": metadata.get("category") or "sast",
            "target": display_local_target(path, local_path, remote_scan_path),
            "id": item.get("check_id") or "semgrep",
            "severity": severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} else "MEDIUM",
            "package": "",
            "installed_version": "",
            "fixed_version": "",
            "title": extra.get("message") or "Achado SAST Semgrep",
            "remediation": metadata.get("remediation") or recommended_sast_action(item),
            "scanner": "semgrep",
            "line": item.get("start", {}).get("line"),
        })
    return {"semgrep_status": "success", "findings": findings}


def is_ignored_source_path(path, root):
    ignored = {".git", "node_modules", "vendor", ".cache", "tmp", "logs", "log", "backup", "backups"}
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return any(part in ignored for part in parts[:-1])


def scan_php_lfi(path, root, remote_path, text):
    findings = []
    tainted_vars = set(re.findall(r"(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[", text))
    include_re = re.compile(r"\b(include|include_once|require|require_once)\s*(?:\(?\s*)([^;\n]+)", re.IGNORECASE)
    for match in include_re.finditer(text):
        expr = match.group(2)
        direct_input = re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[", expr)
        tainted_input = any(var in expr for var in tainted_vars)
        if not direct_input and not tainted_input:
            continue
        relative = path.relative_to(root)
        target = display_remote_path(remote_path, relative)
        findings.append({
            "type": "lfi",
            "target": target,
            "id": "PHP-LFI-001",
            "severity": "HIGH",
            "package": "",
            "installed_version": "",
            "fixed_version": "",
            "title": "Possivel Local File Inclusion em include/require com entrada controlada pelo usuario.",
            "remediation": (
                "Validar o parametro contra uma lista permitida de paginas, normalizar o caminho com realpath "
                "e bloquear sequencias como ../ antes de chamar include/require."
            ),
            "scanner": "fallback-sast",
        })
        break
    return findings


def display_scan_target(target, local_root, remote_scan_path):
    if not target:
        return ""
    target_path = Path(str(target))
    if target_path.is_absolute():
        return str(target_path)
    return display_local_target(local_root / target_path, local_root, remote_scan_path)


def display_local_target(path, local_root, remote_scan_path):
    path = Path(path)
    try:
        relative = path.relative_to(local_root)
    except ValueError:
        return str(path)
    return display_remote_path(remote_scan_path, relative)


def display_remote_path(remote_path, relative):
    remote_root = Path(remote_path)
    parts = relative.parts
    client = remote_root.parent.name if remote_root.name == "files" else remote_root.name
    volume_prefixes = [
        ("docker-data", "volumes", f"{client}_html_data", "_data"),
        ("docker-data", "volumes", f"{client}_webserver_data", "_data"),
    ]
    for prefix in volume_prefixes:
        if parts[:len(prefix)] == prefix:
            return str(remote_root / "files" / Path(*parts[len(prefix):]))
    return str(remote_root / relative)


def load_toml(path):
    if not path.exists():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_code_allowlist(root):
    return load_toml(root / "config" / "code_scan_allowlist.toml").get("allowlist", [])


def load_code_severity_policy(root):
    data = load_toml(root / "config" / "code_severity_policy.toml")
    return data.get("rules", []) or []


def apply_code_policy(summary, client, allowlist, severity_policy):
    kept = []
    suppressed = []
    for finding in summary.get("top_findings", []) or []:
        apply_sla(finding, severity_policy)
        if is_allowlisted(finding, client, allowlist):
            suppressed.append(finding)
        else:
            kept.append(finding)
    summary["top_findings"] = kept[:100]
    summary["suppressed_findings"] = len(suppressed)
    summary["suppressed"] = suppressed[:100]
    recalculate_summary_counts(summary)


def apply_sla(finding, severity_policy):
    finding_type = finding.get("type") or ""
    severity = finding.get("severity") or ""
    for rule in severity_policy:
        if rule.get("type") not in ("*", finding_type):
            continue
        if rule.get("severity") not in ("*", severity):
            continue
        if rule.get("classification"):
            finding["classification"] = rule.get("classification")
        if rule.get("sla_days") is not None:
            finding["sla_days"] = rule.get("sla_days")
        return


def is_allowlisted(finding, client, allowlist):
    for rule in allowlist or []:
        if rule.get("enabled", True) is False:
            continue
        if rule.get("client") and rule.get("client") != client:
            continue
        if rule.get("id") and rule.get("id") != finding.get("id"):
            continue
        if rule.get("type") and rule.get("type") != finding.get("type"):
            continue
        target = finding.get("target") or ""
        if rule.get("target") and rule.get("target") != target:
            continue
        if rule.get("target_regex") and not re.search(rule.get("target_regex"), target):
            continue
        finding["allowlist_reason"] = rule.get("reason") or "allowlisted"
        return True
    return False


def recalculate_summary_counts(summary):
    severity_counts = {}
    counts = {
        "vulnerabilities": 0,
        "secrets": 0,
        "misconfigurations": 0,
        "code_findings": 0,
    }
    for finding in summary.get("top_findings", []) or []:
        severity = finding.get("severity") or "UNKNOWN"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        finding_type = finding.get("type")
        if finding_type == "vulnerability":
            counts["vulnerabilities"] += 1
        elif finding_type == "secret":
            counts["secrets"] += 1
        elif finding_type == "misconfiguration":
            counts["misconfigurations"] += 1
        else:
            counts["code_findings"] += 1
    summary.update(counts)
    summary["severity_counts"] = severity_counts


def recommended_sast_action(item):
    check_id = item.get("check_id") or "regra SAST"
    return f"Revisar o achado {check_id}, corrigir o fluxo vulneravel e registrar evidencia de validacao."


def finding_fingerprint(client, finding):
    raw = "|".join(str(value or "") for value in [
        client,
        finding.get("type"),
        finding.get("id"),
        finding.get("target"),
        finding.get("package"),
    ])
    return safe_name(raw)[:180]


def flatten_findings(summary):
    rows = {}
    for result in summary.get("results", []) or []:
        client = result.get("client")
        for finding in result.get("top_findings", []) or []:
            fingerprint = finding_fingerprint(client, finding)
            rows[fingerprint] = {
                "fingerprint": fingerprint,
                "client": client,
                "type": finding.get("type"),
                "id": finding.get("id"),
                "target": finding.get("target"),
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "remediation": finding.get("remediation"),
                "sla_days": finding.get("sla_days"),
                "classification": finding.get("classification"),
            }
    return rows


def previous_code_summary(root, run_id):
    candidates = []
    for path in sorted((root / "output" / "code").glob("code_summary_*.json"), key=lambda item: item.stat().st_mtime):
        if path.name == "code_summary_latest.json":
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("run_id") == run_id:
            continue
        candidates.append(data)
    return candidates[-1] if candidates else {}


def build_code_history(root, current):
    current_rows = flatten_findings(current)
    previous = previous_code_summary(root, current.get("run_id"))
    previous_rows = flatten_findings(previous) if previous else {}
    new_keys = sorted(set(current_rows) - set(previous_rows))
    persistent_keys = sorted(set(current_rows).intersection(previous_rows))
    fixed_keys = sorted(set(previous_rows) - set(current_rows))
    history = {
        "previous_run_id": previous.get("run_id"),
        "new": len(new_keys),
        "persistent": len(persistent_keys),
        "fixed": len(fixed_keys),
        "new_findings": [current_rows[key] for key in new_keys[:100]],
        "persistent_findings": [current_rows[key] for key in persistent_keys[:100]],
        "fixed_findings": [previous_rows[key] for key in fixed_keys[:100]],
    }
    history_dir = root / "output" / "code-history"
    history_dir.mkdir(parents=True, exist_ok=True)
    path = history_dir / f"code_history_{current.get('run_id')}.json"
    path.write_text(json.dumps(history, indent=2, sort_keys=True), encoding="utf-8")
    (history_dir / "code_history_latest.json").write_text(json.dumps(history, indent=2, sort_keys=True), encoding="utf-8")
    return history


def vulnerability_remediation(vuln):
    package = vuln.get("PkgName") or "pacote afetado"
    fixed = vuln.get("FixedVersion")
    severity = vuln.get("Severity") or "UNKNOWN"
    if fixed:
        return f"Atualizar {package} para {fixed} e validar compatibilidade no projeto."
    if severity in {"CRITICAL", "HIGH"}:
        return "Sem versao corrigida informada; avaliar mitigacao, troca da dependencia ou compensacao de risco."
    return "Monitorar a dependencia e atualizar quando houver versao corrigida."


def secret_remediation(secret):
    rule = secret.get("RuleID") or "secret"
    return (
        f"Remover o {rule} do repositorio/diretorio, rotacionar a credencial no provedor e "
        "substituir por variavel de ambiente ou secret manager."
    )


def misconfiguration_remediation(misconfig):
    resolution = misconfig.get("Resolution")
    if resolution:
        return resolution
    message = misconfig.get("Message") or misconfig.get("Title") or "configuracao insegura"
    return f"Revisar a configuracao apontada pelo Trivy e ajustar o item: {message}"


def sanitize(value):
    text = value or ""
    text = re.sub(r"(?i)(api[_-]?key|token|password|secret)=\S+", r"\1=<redacted>", text)
    return text[-4000:]


def main():
    parser = argparse.ArgumentParser(description="Scan remote client code directories with central Trivy fs.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--timeout", type=int, default=900)
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
    if inventory.get("status") == "failed":
        print("inventory failed; refusing to overwrite latest code report with empty target list", file=sys.stderr)
        return 2
    work_dir = root / "tmp" / "code-scan" / args.run_id
    output = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "status": "unknown",
        "clients_total": 0,
        "success": 0,
        "failed": 0,
        "skipped": 0,
        "totals": {
            "vulnerabilities": 0,
            "secrets": 0,
            "misconfigurations": 0,
            "code_findings": 0,
            "suppressed_findings": 0,
            "severity_counts": {},
        },
        "results": [],
    }

    targets = code_targets(inventory)
    if not targets:
        print("no code targets discovered from inventory contexts; refusing to overwrite latest code report", file=sys.stderr)
        return 2
    try:
        output["clients_total"] = len(targets)
        for target in targets:
            print(f"code_scan client={target['client']} host={target['host'].get('ip')}", flush=True)
            target["scan_path"] = choose_scan_path(target)
            row = {
                "client": target["client"],
                "host_name": target.get("host_name"),
                "host_ip": target["host"].get("ip"),
                "remote_path": target["remote_path"],
                "scan_path": target["scan_path"],
            }
            if not remote_path_exists(target):
                row["status"] = "skipped_path_missing"
                output["skipped"] += 1
                output["results"].append(row)
                continue
            local_root = work_dir / safe_name(target["client"])
            copied = copy_remote_code(target, local_root, args.timeout)
            if copied.get("status") != "copied":
                row.update(copied)
                output["failed"] += 1
                output["results"].append(row)
                continue
            scanned = run_trivy_code(root, args.run_id, target, copied["local_path"], args.timeout)
            row.update(scanned)
            if scanned.get("status") == "success":
                output["success"] += 1
                for key in ("vulnerabilities", "secrets", "misconfigurations", "code_findings", "suppressed_findings"):
                    output["totals"][key] += int(scanned.get(key) or 0)
                for severity, count in (scanned.get("severity_counts") or {}).items():
                    output["totals"]["severity_counts"][severity] = output["totals"]["severity_counts"].get(severity, 0) + int(count or 0)
            else:
                output["failed"] += 1
            output["results"].append(row)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    if output["failed"]:
        output["status"] = "partial_success" if output["success"] or output["skipped"] else "failed"
    else:
        output["status"] = "success"

    out_dir = root / "output" / "code"
    out_dir.mkdir(parents=True, exist_ok=True)
    output["history"] = build_code_history(root, output)
    out_path = out_dir / f"code_summary_{args.run_id}.json"
    out_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "code_summary_latest.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    if output["status"] == "failed":
        return 2
    if output["status"] == "partial_success":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
