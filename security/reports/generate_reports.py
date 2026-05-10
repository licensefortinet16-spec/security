#!/usr/bin/env python3
import argparse
import csv
import html
import json
import os
import re
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_POINTS = {
    "critical": 30,
    "high": 15,
    "medium": 5,
    "low": 1,
    "informational": 0,
}

TYPE_POINTS = {
    "privileged_container": 20,
    "docker_socket_mounted": 25,
    "running_as_root": 10,
    "latest_tag": 5,
    "public_port_exposed": 10,
    "sensitive_host_path_mounted": 15,
    "host_network_mode": 20,
    "host_pid_mode": 20,
    "dangerous_capability": 20,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
FINDING_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

SLA_BY_SEVERITY = {
    "CRITICAL": "7 dias",
    "HIGH": "15 dias",
    "MEDIUM": "30 dias",
    "LOW": "90 dias",
    "UNKNOWN": "triagem",
    "critical": "7 dias",
    "high": "15 dias",
    "medium": "30 dias",
    "low": "90 dias",
}

MITRE_BY_FINDING = {
    "docker_socket_mounted": ["Privilege Escalation", "Defense Evasion"],
    "privileged_container": ["Privilege Escalation", "Defense Evasion"],
    "sensitive_host_path_mounted": ["Privilege Escalation", "Collection"],
    "running_as_root": ["Privilege Escalation"],
    "public_port_exposed": ["Initial Access"],
    "host_network_mode": ["Defense Evasion", "Discovery"],
    "host_pid_mode": ["Privilege Escalation"],
    "dangerous_capability": ["Privilege Escalation"],
    "latest_tag": ["Defense Evasion"],
}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def latest(path, pattern, run_id):
    exact = path / pattern.format(run_id=run_id)
    if exact.exists():
        return exact
    candidates = sorted(path.glob(pattern.format(run_id="*")))
    return candidates[-1] if candidates else None


def esc(value):
    return html.escape(str(value if value is not None else ""))


def slugify(value):
    text = str(value if value is not None else "unknown").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "unknown"


def container_slug(row):
    return slugify(f"{row.get('host_name')}-{row.get('container_name')}-{row.get('image')}")


def classify(score):
    if score <= 30:
        return "baixo"
    if score <= 60:
        return "medio"
    if score <= 80:
        return "alto"
    return "critico"


def score_findings(findings, inventory=None, image_vulns=None):
    by_container = defaultdict(lambda: {"score": 0, "factors": [], "findings": 0})
    context_map = {}
    if inventory:
        for host in inventory.get("hosts", []):
            for container in host.get("containers", []):
                key = (
                    container.get("host_name") or "unknown",
                    container.get("name") or "unknown",
                    container.get("image") or "unknown",
                )
                context_map[key] = container.get("context") or "docker default"
    for finding in findings:
        key = (
            finding.get("host_name") or "unknown",
            finding.get("container_name") or "unknown",
            finding.get("image") or "unknown",
        )
        points = SEVERITY_POINTS.get((finding.get("severity") or "").lower(), 0)
        points += TYPE_POINTS.get(finding.get("type"), 0)
        item = by_container[key]
        item["score"] = min(100, item["score"] + points)
        item["findings"] += 1
        item["factors"].append({
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "points": points,
            "evidence": finding.get("evidence"),
        })

    image_vulns = image_vulns or {}
    if inventory:
        for host in inventory.get("hosts", []):
            for container in host.get("containers", []):
                key = (
                    container.get("host_name") or "unknown",
                    container.get("name") or "unknown",
                    container.get("image") or "unknown",
                )
                item = by_container[key]
                for vuln in image_vulns.get(container.get("image"), []):
                    severity = (vuln.get("Severity") or "").lower()
                    points = SEVERITY_POINTS.get(severity, 0)
                    if not points:
                        continue
                    item["score"] = min(100, item["score"] + points)
                    item["findings"] += 1
                    if len(item["factors"]) < 40:
                        item["factors"].append({
                            "type": "vulnerability",
                            "severity": severity,
                            "points": points,
                            "evidence": vuln.get("VulnerabilityID"),
                        })

    rows = []
    for (host, container, image), value in by_container.items():
        score = min(100, value["score"])
        rows.append({
            "host_name": host,
            "container_name": container,
            "image": image,
            "context": context_map.get((host, container, image), "docker default"),
            "score": score,
            "classification": classify(score),
            "findings": value["findings"],
            "factors": value["factors"],
        })
    return sorted(rows, key=lambda row: row["score"], reverse=True)


def load_vulnerabilities(trivy_summary):
    output = {
        "total": 0,
        "severity_counts": {},
        "by_image": {},
        "top_vulnerabilities": [],
    }
    if not trivy_summary:
        return output

    for result in trivy_summary.get("results", []):
        if result.get("status") != "success":
            continue
        image = result.get("image")
        path = result.get("vulnerability_output")
        if not image or not path or not Path(path).exists():
            continue
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        vulns = []
        for trivy_result in data.get("Results", []) or []:
            for vuln in trivy_result.get("Vulnerabilities", []) or []:
                severity = vuln.get("Severity") or "UNKNOWN"
                output["severity_counts"][severity] = output["severity_counts"].get(severity, 0) + 1
                output["total"] += 1
                normalized = {
                    "image": image,
                    "id": vuln.get("VulnerabilityID"),
                    "severity": severity,
                    "package": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "title": vuln.get("Title") or vuln.get("Description", "")[:120],
                }
                vulns.append(vuln)
                output["top_vulnerabilities"].append(normalized)
        output["by_image"][image] = vulns

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    output["top_vulnerabilities"].sort(key=lambda row: (severity_order.get(row.get("severity"), 9), row.get("image") or "", row.get("id") or ""))
    return output


def summarize_context(rows):
    summary = {}
    for row in rows:
        context = row.get("context") or "docker default"
        item = summary.setdefault(context, {
            "context": context,
            "containers": 0,
            "score_max": 0,
            "score_sum": 0,
            "score_avg": 0,
            "findings": 0,
            "critical_containers": 0,
            "high_containers": 0,
        })
        score = int(row.get("score", 0) or 0)
        item["containers"] += 1
        item["score_sum"] += score
        item["score_max"] = max(item["score_max"], score)
        item["findings"] += int(row.get("findings", 0) or 0)
        if row.get("classification") == "critico":
            item["critical_containers"] += 1
        elif row.get("classification") == "alto":
            item["high_containers"] += 1
    for item in summary.values():
        item["score_avg"] = round(item["score_sum"] / item["containers"], 2) if item["containers"] else 0
    return sorted(summary.values(), key=lambda row: (row["score_max"], row["findings"], row["context"]), reverse=True)


def load_context_trend(root):
    rows = []
    for path in sorted((root / "output" / "history").glob("risk_scores_*.json")):
        if path.name == "risk_scores_latest.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        context_rows = summarize_context(data.get("scores", []) or [])
        rows.append({
            "run_id": data.get("run_id") or path.stem.replace("risk_scores_", ""),
            "contexts": context_rows,
        })
    return rows[-8:]


def render_executive(run_id, inventory, risk_rows, vuln_summary, dtrack_summary, dtrack_analysis, trivy_summary, trend_rows, context_summary, context_trend):
    summary = inventory.get("summary", {})
    max_score = risk_rows[0]["score"] if risk_rows else 0
    status = classify(max_score)
    dtrack_status = dtrack_summary.get("status") if dtrack_summary else "nao_executado"
    dtrack_analysis_status = dtrack_analysis.get("status") if dtrack_analysis else "nao_executado"
    dtrack_totals = (dtrack_analysis or {}).get("totals") or {}
    severity_counts = vuln_summary.get("severity_counts") or {}
    finding_severity = summary.get("findings_by_severity") or {}
    top = risk_rows[:8]
    actions = build_priority_actions(risk_rows, vuln_summary, inventory)[:8]
    tactics = top_mitre_tactics(inventory, vuln_summary)[:5]

    return base_html(
        "Relatorio Gerencial - Container Security Monitor",
        f"""
        <section class="hero">
          <div>
            <p class="eyebrow">Container Security Monitor</p>
            <h1>Relatorio Gerencial</h1>
            <p class="muted">Execucao {esc(run_id)} - gerado em {esc(utc_now())}</p>
            <p class="hero-actions"><a href="/reports/executive.pdf">Exportar PDF completo</a></p>
          </div>
          <div class="risk-card {esc(status)}">
            <span>Risco geral</span>
            <strong>{esc(status.upper())}</strong>
            <em>score {esc(max_score)}/100</em>
          </div>
        </section>

        <section class="kpis">
          {kpi("Hosts", f"{summary.get('hosts_success', 0)}/{summary.get('hosts_total', 0)}", "analisados")}
          {kpi("Containers", summary.get("containers_total", 0), "inventariados")}
          {kpi("Imagens", summary.get("images_total", 0), "em uso")}
          {kpi("Vulnerabilidades", vuln_summary.get("total", 0), "Trivy central")}
          {kpi("Criticas", severity_counts.get("CRITICAL", 0), "CVEs")}
          {kpi("Altas", severity_counts.get("HIGH", 0), "CVEs")}
          {kpi("DT vulns", dtrack_totals.get("dtrack_vulnerabilities", 0), "correlacionadas")}
        </section>

        {dtrack_correlation_notice(vuln_summary, dtrack_analysis)}

        <section class="grid two">
          <div class="panel">
            <h2>Vulnerabilidades por Severidade</h2>
            {horizontal_bars(severity_counts, SEVERITY_ORDER, severity_class)}
          </div>
          <div class="panel">
            <h2>Achados de Configuracao</h2>
            {horizontal_bars(finding_severity, FINDING_SEVERITY_ORDER, severity_class)}
          </div>
        </section>

        <section class="panel">
          <h2>Top Containers por Risco</h2>
          {risk_bars(top)}
        </section>

        <section class="grid two">
          <div class="panel">
            <h2>Contextos Prioritarios</h2>
            {context_table(context_summary[:6])}
          </div>
          <div class="panel">
            <h2>Contexto Dominante em Tendencia</h2>
            {context_trend_chart(context_trend[:6])}
          </div>
        </section>

        <section class="grid two">
          <div class="panel">
            <h2>Plano de Acao Prioritario</h2>
            {priority_list(actions)}
          </div>
          <div class="panel">
            <h2>MITRE ATT&CK Aproximado</h2>
            {tactic_list(tactics)}
          </div>
        </section>

        <section class="panel">
          <h2>Tendencia Historica</h2>
          {trend_chart(trend_rows)}
        </section>

        <section class="grid two">
          <div class="panel">
            <h2>Status Operacional</h2>
            <table class="clean">
              <tr><th>Inventario</th><td>{badge(inventory.get('status'))}</td></tr>
              <tr><th>Trivy</th><td>{esc((trivy_summary or {}).get('success', 0))} sucesso / {esc((trivy_summary or {}).get('failed', 0))} falhas</td></tr>
              <tr><th>Dependency-Track</th><td>{badge(dtrack_status)}</td></tr>
              <tr><th>Correlacao DT</th><td>{badge(dtrack_analysis_status)}</td></tr>
              <tr><th>SBOMs enviados</th><td>{esc((dtrack_summary or {}).get('uploaded', 0))}</td></tr>
            </table>
          </div>
          <div class="panel">
            <h2>Prioridade Recomendada</h2>
            <ol class="priority">
              <li>Tratar containers com score 100 e CVEs criticas.</li>
              <li>Substituir tags <code>latest</code> por versoes fixas.</li>
              <li>Remover execucao como root quando possivel.</li>
              <li>Definir limites de CPU/memoria e healthchecks.</li>
              <li>Disponibilizar imagens privadas ao scanner central via registry.</li>
            </ol>
          </div>
        </section>
        """,
    )


def technical_nav(risk_rows, selected_slug=None):
    rows = [
        f'<a class="nav-button {"active" if not selected_slug else ""}" href="/reports/technical"><strong>Todos os containers</strong><span>visao completa</span></a>'
    ]
    for row in risk_rows:
        slug = container_slug(row)
        rows.append(
            f"""<a class="nav-button {"active" if slug == selected_slug else ""}" href="/reports/technical/containers/{esc(slug)}">
              <strong>{esc(row.get('container_name'))}</strong>
              <span>{esc(row.get('context'))} - score {esc(row.get('score'))}</span>
            </a>"""
        )
    sections = [
        ("#vulnerabilidades-container", "Vulnerabilidades por Container", "ranking e CVEs"),
        ("#score-container", "Score por Container", "risco tecnico"),
        ("#vulnerabilidades-prioritarias", "Vulnerabilidades Prioritarias", "pacotes e versoes"),
        ("#achados-configuracao", "Achados de Configuracao", "hardening"),
        ("#dependency-track", "Dependency-Track", "correlacao"),
    ]
    section_links = "".join(
        f'<a class="nav-button secondary" href="{href}"><strong>{esc(label)}</strong><span>{esc(helper)}</span></a>'
        for href, label, helper in sections
    )
    return f"""
    <aside class="side-nav">
      <h2>Menu Tecnico</h2>
      <details class="nav-group" open>
        <summary>Containers</summary>
        <div class="nav-items">{"".join(rows)}</div>
      </details>
      <details class="nav-group" open>
        <summary>Secoes do Relatorio</summary>
        <div class="nav-items">{section_links}</div>
      </details>
    </aside>
    """


def filter_container_findings(findings, row):
    return [
        item for item in findings
        if (item.get("host_name") or "unknown") == row.get("host_name")
        and (item.get("container_name") or "unknown") == row.get("container_name")
        and (item.get("image") or "unknown") == row.get("image")
    ]


def vulnerability_rows_for_images(vuln_summary, images, limit=250):
    image_set = set(images)
    rows = []
    for row in vuln_summary.get("top_vulnerabilities", []):
        if row.get("image") not in image_set:
            continue
        rows.append(
            "<tr>"
            f"<td>{esc(row.get('image'))}</td>"
            f"<td>{esc(row.get('id'))}</td>"
            f"<td>{badge(row.get('severity'))}</td>"
            f"<td>{esc(row.get('package'))}</td>"
            f"<td>{esc(row.get('installed_version'))}</td>"
            f"<td>{esc(row.get('fixed_version'))}</td>"
            f"<td>{esc(row.get('title'))}</td>"
            "</tr>"
        )
        if len(rows) >= limit:
            break
    if not rows:
        return '<tr><td colspan="7" class="muted">Sem vulnerabilidades para o filtro selecionado.</td></tr>'
    return "".join(rows)


def vulnerability_container_index(risk_rows, vuln_summary):
    by_image = vuln_summary.get("by_image") or {}
    rows = []
    for row in risk_rows:
        vulns = by_image.get(row.get("image"), [])
        counts = defaultdict(int)
        for vuln in vulns:
            counts[vuln.get("Severity") or "UNKNOWN"] += 1
        rows.append(
            "<tr>"
            f"<td><a class=\"table-action\" href=\"/reports/technical/containers/{esc(container_slug(row))}\">{esc(row.get('container_name'))}</a></td>"
            f"<td>{esc(row.get('context'))}</td>"
            f"<td>{esc(row.get('image'))}</td>"
            f"<td>{esc(len(vulns))}</td>"
            f"<td>{esc(counts.get('CRITICAL', 0))}</td>"
            f"<td>{esc(counts.get('HIGH', 0))}</td>"
            f"<td>{esc(row.get('score'))}</td>"
            "</tr>"
        )
    if not rows:
        return '<p class="muted">Sem containers para listar nesta execucao.</p>'
    return f"""
    <div class="table-wrap">
      <table>
        <tr><th>Container</th><th>Contexto</th><th>Imagem</th><th>CVEs</th><th>Criticas</th><th>Altas</th><th>Score</th></tr>
        {''.join(rows)}
      </table>
    </div>
    """


def severity_counts_for_images(vuln_summary, images):
    counts = {}
    by_image = vuln_summary.get("by_image") or {}
    for image in images:
        for vuln in by_image.get(image, []):
            severity = vuln.get("Severity") or "UNKNOWN"
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def finding_types_for_rows(findings):
    counts = {}
    for finding in findings:
        finding_type = finding.get("type") or "unknown"
        counts[finding_type] = counts.get(finding_type, 0) + 1
    return counts


def render_technical(run_id, inventory, findings, risk_rows, trivy_summary, vuln_summary, dtrack_summary, dtrack_analysis, context_summary, selected_container=None):
    summary = inventory.get("summary", {})
    selected_slug = container_slug(selected_container) if selected_container else None
    visible_risk_rows = [selected_container] if selected_container else risk_rows
    visible_findings = filter_container_findings(findings, selected_container) if selected_container else findings
    visible_images = [selected_container.get("image")] if selected_container else sorted({row.get("image") for row in risk_rows if row.get("image")})
    severity_counts = severity_counts_for_images(vuln_summary, visible_images) if selected_container else (vuln_summary.get("severity_counts") or {})
    finding_types = finding_types_for_rows(visible_findings) if selected_container else (summary.get("findings_by_type") or {})
    visible_context_summary = summarize_context(visible_risk_rows) if selected_container else context_summary
    visible_vuln_summary = dict(vuln_summary)
    visible_vuln_summary["severity_counts"] = severity_counts
    actions = build_priority_actions(visible_risk_rows, visible_vuln_summary, inventory)
    tactics = top_mitre_tactics({"hosts": [{"findings": visible_findings}], "summary": summary}, visible_vuln_summary) if selected_container else top_mitre_tactics(inventory, vuln_summary)

    finding_rows = []
    for finding in visible_findings:
        finding_rows.append(
            "<tr>"
            f"<td>{esc(finding.get('host_name'))}</td>"
            f"<td>{esc(finding.get('container_name'))}</td>"
            f"<td>{esc(finding.get('severity'))}</td>"
            f"<td>{esc(finding.get('type'))}</td>"
            f"<td>{esc(finding.get('evidence'))}</td>"
            f"<td>{esc(finding.get('recommendation'))}</td>"
            "</tr>"
        )
    if not finding_rows:
        finding_rows.append('<tr><td colspan="6" class="muted">Sem achados de configuracao para o filtro selecionado.</td></tr>')

    risk_rows_html = []
    for row in visible_risk_rows:
        risk_rows_html.append(
            "<tr>"
            f"<td>{esc(row['host_name'])}</td>"
            f"<td>{esc(row['container_name'])}</td>"
            f"<td>{esc(row['image'])}</td>"
            f"<td><strong>{esc(row['score'])}</strong></td>"
            f"<td>{badge(row['classification'])}</td>"
            f"<td>{esc(row['findings'])}</td>"
            "</tr>"
        )

    vuln_rows = vulnerability_rows_for_images(vuln_summary, visible_images, limit=300 if selected_container else 150)

    trivy_failures = []
    for item in (trivy_summary or {}).get("results", []):
        if selected_container and item.get("image") not in visible_images:
            continue
        if item.get("status") != "success":
            trivy_failures.append(
                "<tr>"
                f"<td>{esc(item.get('image'))}</td>"
                f"<td>{badge(item.get('status'))}</td>"
                f"<td>{esc(item.get('stage'))}</td>"
                f"<td>{esc(item.get('stderr'))}</td>"
                "</tr>"
            )

    dtrack_rows = []
    for item in (dtrack_summary or {}).get("results", []):
        if selected_container and item.get("image") not in visible_images:
            continue
        dtrack_rows.append(
            "<tr>"
            f"<td>{esc(item.get('image'))}</td>"
            f"<td>{badge(item.get('status'))}</td>"
            f"<td>{esc(item.get('http_status'))}</td>"
            f"<td>{esc(item.get('error'))}</td>"
            "</tr>"
        )

    scope_title = f" - {selected_container.get('container_name')}" if selected_container else ""
    scope_kpis = ""
    if selected_container:
        scope_kpis = f"""
          {kpi("Contexto", selected_container.get("context"), "origem")}
          {kpi("Score", selected_container.get("score"), selected_container.get("classification"))}
          {kpi("Achados", selected_container.get("findings"), "container")}
        """

    content = f"""
    <div class="technical-layout">
      {technical_nav(risk_rows, selected_slug)}
      <main class="technical-main">
        <section class="hero compact">
          <div>
            <p class="eyebrow">Container Security Monitor</p>
            <h1>Relatorio Tecnico{esc(scope_title)}</h1>
            <p class="muted">Execucao {esc(run_id)} - inventario {esc(inventory.get('status'))}</p>
          </div>
        </section>

        <section class="kpis inline">
          {kpi("Hosts", f"{summary.get('hosts_success', 0)}/{summary.get('hosts_total', 0)}", "OK")}
          {kpi("Containers", len(visible_risk_rows) if selected_container else summary.get("containers_total", 0), "Docker")}
          {kpi("Imagens", len(visible_images), "unicas")}
          {kpi("Achados", len(visible_findings) if selected_container else summary.get("findings_total", 0), "config")}
          {kpi("CVEs", len((vuln_summary.get("by_image") or {}).get(selected_container.get("image"), [])) if selected_container else vuln_summary.get("total", 0), "Trivy")}
          {kpi("SBOM upload", (dtrack_summary or {}).get("uploaded", 0), "Dependency-Track")}
          {kpi("DT CVEs", ((dtrack_analysis or {}).get("totals") or {}).get("dtrack_vulnerabilities", 0), "correlacionadas")}
          {scope_kpis}
        </section>

        {dtrack_correlation_notice(vuln_summary, dtrack_analysis)}

        <section class="grid two">
          <div class="panel">
            <h2>CVEs por Severidade</h2>
            {horizontal_bars(severity_counts, SEVERITY_ORDER, severity_class)}
          </div>
          <div class="panel">
            <h2>Tipos de Achado</h2>
            {horizontal_bars(finding_types, sorted(finding_types, key=finding_types.get, reverse=True), lambda _: "info")}
          </div>
        </section>

        <section id="vulnerabilidades-container" class="panel">
          <h2>Vulnerabilidades por Container</h2>
          {vulnerability_container_index(visible_risk_rows, vuln_summary)}
        </section>

        <section id="contextos-prioritarios" class="panel">
          <h2>Contextos Prioritarios</h2>
          {context_table(visible_context_summary[:8])}
        </section>

        <section id="score-container" class="panel">
          <h2>Score por Container</h2>
          <div class="table-wrap">
            <table>
              <tr><th>Host</th><th>Container</th><th>Imagem</th><th>Score</th><th>Classe</th><th>Achados</th></tr>
              {''.join(risk_rows_html)}
            </table>
          </div>
        </section>

        <section id="plano-acao" class="grid two">
          <div class="panel">
            <h2>Plano de Acao com SLA</h2>
            {priority_table(actions)}
          </div>
          <div class="panel">
            <h2>Correlacao MITRE ATT&CK</h2>
            <p class="muted">Mapeamento aproximado por tipo de achado e severidade; nao representa atribuicao absoluta de tecnica.</p>
            {tactic_list(tactics)}
          </div>
        </section>

        <section id="vulnerabilidades-prioritarias" class="panel">
          <h2>Vulnerabilidades Prioritarias</h2>
          <div class="table-wrap">
            <table>
              <tr><th>Imagem</th><th>ID</th><th>Severidade</th><th>Pacote</th><th>Instalada</th><th>Corrigida</th><th>Titulo</th></tr>
              {vuln_rows}
            </table>
          </div>
        </section>

        <section id="achados-configuracao" class="panel">
          <h2>Achados de Configuracao</h2>
          <div class="table-wrap">
            <table>
              <tr><th>Host</th><th>Container</th><th>Severidade</th><th>Tipo</th><th>Evidencia</th><th>Recomendacao</th></tr>
              {''.join(finding_rows)}
            </table>
          </div>
        </section>

        <section id="operacional" class="grid two">
          <div class="panel">
            <h2>Falhas Trivy Tratadas</h2>
            <table>
              <tr><th>Imagem</th><th>Status</th><th>Etapa</th><th>Erro sanitizado</th></tr>
              {''.join(trivy_failures)}
            </table>
          </div>
          <div class="panel">
            <h2>Dependency-Track</h2>
            <table>
              <tr><th>Imagem</th><th>Status</th><th>HTTP</th><th>Erro</th></tr>
              {''.join(dtrack_rows)}
            </table>
          </div>
        </section>

        <section id="dependency-track" class="panel">
          <h2>Correlacao Dependency-Track</h2>
          {dtrack_project_table(dtrack_analysis, visible_images if selected_container else None)}
        </section>
      </main>
    </div>
    """

    return base_html(
        "Relatorio Tecnico - Container Security Monitor",
        content,
    )


def render_index(run_id, inventory, risk_rows, vuln_summary, dtrack_summary, dtrack_analysis, trend_rows):
    summary = inventory.get("summary", {})
    max_score = max([item.get("score", 0) for item in risk_rows] or [0])
    return base_html(
        "Container Security Monitor - Latest",
        f"""
        <section class="hero">
          <div>
            <p class="eyebrow">Container Security Monitor</p>
            <h1>Ultima Execucao</h1>
            <p class="muted">{esc(run_id)} - gerado em {esc(utc_now())}</p>
          </div>
          <div class="risk-card {esc(classify(max_score))}">
            <span>Score maximo</span>
            <strong>{esc(max_score)}</strong>
            <em>{esc(classify(max_score))}</em>
          </div>
        </section>
        <section class="kpis">
          {kpi("Hosts", f"{summary.get('hosts_success')}/{summary.get('hosts_total')}", "analisados")}
          {kpi("Containers", summary.get("containers_total", 0), "inventario")}
          {kpi("CVEs", vuln_summary.get("total", 0), "Trivy")}
          {kpi("SBOMs", (dtrack_summary or {}).get("uploaded", 0), "enviados")}
          {kpi("DT CVEs", ((dtrack_analysis or {}).get("totals") or {}).get("dtrack_vulnerabilities", 0), "correlacionadas")}
        </section>
        {dtrack_correlation_notice(vuln_summary, dtrack_analysis)}
        <section class="panel">
          <h2>Tendencia</h2>
          {trend_chart(trend_rows[-6:])}
        </section>
        <section class="panel">
          <h2>Relatorios</h2>
          <div class="actions">
            <a href="executive_report_latest.html">Relatorio gerencial</a>
            <a href="technical_report_latest.html">Relatorio tecnico</a>
            <a href="http://192.168.1.22:8090">Painel do scanner</a>
            <a href="http://192.168.1.22:8080">Dependency-Track</a>
          </div>
        </section>
        """,
    )


def base_html(title, body):
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)}</title>
  <style>
    :root {{
      --bg: #f6f8fb;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #64748b;
      --line: #d9e2ec;
      --critical: #b42318;
      --high: #c2410c;
      --medium: #b7791f;
      --low: #2f855a;
      --info: #2563eb;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font-family: Arial, Helvetica, sans-serif; }}
    h1, h2 {{ margin: 0; color: #102a43; letter-spacing: 0; }}
    h1 {{ font-size: 32px; }}
    h2 {{ font-size: 18px; margin-bottom: 16px; }}
    code {{ background: #edf2f7; padding: 2px 5px; border-radius: 4px; }}
    .hero {{ display: flex; justify-content: space-between; align-items: stretch; gap: 24px; padding: 30px 34px; background: #102a43; color: #fff; }}
    .hero.compact {{ padding: 24px 34px; }}
    .hero h1, .hero .muted, .hero .eyebrow {{ color: #fff; }}
    .hero-actions {{ margin: 14px 0 0; }}
    .hero-actions a {{ display: inline-block; background: #ffffff; color: #102a43; text-decoration: none; font-weight: 700; padding: 9px 12px; border-radius: 6px; }}
    .eyebrow {{ text-transform: uppercase; font-size: 12px; font-weight: 700; letter-spacing: 1px; margin: 0 0 8px; }}
    .muted {{ color: var(--muted); }}
    .risk-card {{ min-width: 210px; background: rgba(255,255,255,.12); border: 1px solid rgba(255,255,255,.24); border-radius: 8px; padding: 18px; display: grid; gap: 4px; }}
    .risk-card span, .risk-card em {{ color: #d9e2ec; font-style: normal; }}
    .risk-card strong {{ font-size: 34px; }}
    .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; padding: 20px 34px 0; }}
    .kpis.inline {{ padding-left: 0; padding-right: 0; }}
    .kpi {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }}
    .kpi span {{ color: var(--muted); font-size: 13px; }}
    .kpi strong {{ display: block; font-size: 28px; margin: 6px 0; }}
    .grid {{ display: grid; gap: 18px; padding: 20px 34px 0; }}
    .grid.two {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; margin: 20px 34px 0; padding: 20px; }}
    .grid .panel {{ margin: 0; }}
    .notice {{ border-left: 5px solid var(--info); background: #eff6ff; }}
    .notice.warning {{ border-left-color: var(--high); background: #fff7ed; }}
    .notice p {{ margin: 0; line-height: 1.45; }}
    .bar-row {{ display: grid; grid-template-columns: 120px 1fr 56px; gap: 10px; align-items: center; margin: 10px 0; }}
    .track {{ height: 14px; background: #e6edf5; border-radius: 999px; overflow: hidden; }}
    .bar {{ height: 100%; border-radius: 999px; }}
    .bar.critical, .bar.critico {{ background: var(--critical); }}
    .bar.high, .bar.alto {{ background: var(--high); }}
    .bar.medium, .bar.medio {{ background: var(--medium); }}
    .bar.low, .bar.baixo {{ background: var(--low); }}
    .bar.info, .bar.unknown, .bar.informational {{ background: var(--info); }}
    .risk-bars .bar-row {{ grid-template-columns: 250px 1fr 48px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 9px; text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ background: #f0f4f8; color: #334e68; }}
    .table-wrap {{ overflow-x: auto; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; color: #fff; background: var(--info); }}
    .badge.critical, .badge.critico, .badge.failed, .badge.upload_failed {{ background: var(--critical); }}
    .badge.high, .badge.alto, .badge.partial_success {{ background: var(--high); }}
    .badge.medium, .badge.medio, .badge.skipped_no_sbom, .badge.image_unavailable_for_central_scan {{ background: var(--medium); }}
    .badge.low, .badge.baixo, .badge.success, .badge.uploaded {{ background: var(--low); }}
    .actions {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .actions a {{ background: #0b5cad; color: #fff; text-decoration: none; padding: 10px 12px; border-radius: 6px; }}
    .technical-layout {{ display: grid; grid-template-columns: 280px minmax(0, 1fr); min-height: 100vh; }}
    .technical-main {{ min-width: 0; padding-bottom: 34px; }}
    .technical-layout .hero, .technical-layout .grid, .technical-layout .panel, .technical-layout .kpis {{ margin-left: 20px; margin-right: 24px; }}
    .technical-layout .grid {{ padding-left: 20px; padding-right: 24px; }}
    .side-nav {{ position: sticky; top: 0; align-self: start; height: 100vh; overflow: auto; background: #0b1f33; border-right: 1px solid #17324d; padding: 18px 14px; }}
    .side-nav h2 {{ color: #fff; font-size: 16px; margin: 0 0 14px; }}
    .nav-group {{ border: 1px solid #1f4568; border-radius: 8px; margin-bottom: 12px; background: rgba(255,255,255,.03); }}
    .nav-group summary {{ cursor: pointer; color: #fff; font-weight: 700; padding: 12px; list-style: none; }}
    .nav-group summary::-webkit-details-marker {{ display: none; }}
    .nav-group summary::after {{ content: "+"; float: right; color: #7cc4ff; }}
    .nav-group[open] summary::after {{ content: "-"; }}
    .nav-items {{ padding: 0 10px 10px; }}
    .nav-button {{ display: grid; gap: 4px; color: #d9e2ec; text-decoration: none; border: 1px solid #244b70; border-radius: 8px; padding: 10px; margin-bottom: 8px; background: #102a43; box-shadow: inset 0 1px 0 rgba(255,255,255,.06); }}
    .nav-button.secondary {{ background: #0f253a; }}
    .nav-button:hover, .nav-button.active {{ background: #0b5cad; border-color: #7cc4ff; color: #fff; }}
    .nav-button strong {{ color: #fff; font-size: 13px; overflow-wrap: anywhere; }}
    .nav-button span {{ color: #bcccdc; font-size: 12px; }}
    .nav-button:hover span, .nav-button.active span {{ color: #e6f4ff; }}
    .table-action {{ display: inline-block; background: #0b5cad; color: #fff; text-decoration: none; font-weight: 700; padding: 7px 9px; border-radius: 6px; }}
    .table-action:hover {{ background: #083f78; }}
    .priority {{ margin: 0; padding-left: 22px; }}
    .legend {{ display: flex; gap: 18px; color: var(--muted); font-size: 13px; margin-bottom: 12px; }}
    .legend i {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; }}
    .legend .score, .trend-bar.score {{ background: #0b5cad; }}
    .legend .critical, .trend-bar.critical {{ background: var(--critical); }}
    .trend {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(92px, 1fr)); gap: 12px; align-items: end; }}
    .trend-item {{ min-height: 190px; display: grid; grid-template-rows: 120px auto auto auto; gap: 4px; text-align: center; color: var(--muted); }}
    .trend-bars {{ height: 120px; display: flex; align-items: end; justify-content: center; gap: 6px; border-bottom: 1px solid var(--line); }}
    .trend-bar {{ width: 18px; border-radius: 4px 4px 0 0; display: inline-block; min-height: 2px; }}
    .trend-item strong {{ color: var(--text); }}
    .trend-item em {{ font-style: normal; font-size: 12px; }}
    @media (max-width: 860px) {{
      .hero {{ flex-direction: column; }}
      .grid.two {{ grid-template-columns: 1fr; }}
      .risk-bars .bar-row, .bar-row {{ grid-template-columns: 1fr; }}
      .technical-layout {{ grid-template-columns: 1fr; }}
      .side-nav {{ position: static; height: auto; }}
      .technical-layout .hero, .technical-layout .grid, .technical-layout .panel, .technical-layout .kpis {{ margin-left: 14px; margin-right: 14px; }}
      .technical-layout .grid {{ padding-left: 14px; padding-right: 14px; }}
    }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def kpi(label, value, helper):
    return f"""<div class="kpi"><span>{esc(label)}</span><strong>{esc(value)}</strong><span>{esc(helper)}</span></div>"""


def severity_class(value):
    return str(value or "info").lower()


def badge(value):
    cls = severity_class(value)
    return f'<span class="badge {esc(cls)}">{esc(value)}</span>'


def horizontal_bars(counts, order, class_fn):
    if not counts:
        return '<p class="muted">Sem dados nesta execucao.</p>'
    max_value = max([int(counts.get(key, 0) or 0) for key in order] or [1]) or 1
    rows = []
    for key in order:
        value = int(counts.get(key, 0) or 0)
        width = max(2, round((value / max_value) * 100)) if value else 0
        rows.append(
            f"""<div class="bar-row">
              <span>{esc(key)}</span>
              <div class="track"><div class="bar {esc(class_fn(key))}" style="width:{width}%"></div></div>
              <strong>{esc(value)}</strong>
            </div>"""
        )
    return "\n".join(rows)


def dtrack_correlation_notice(vuln_summary, dtrack_analysis):
    if not dtrack_analysis:
        return ""
    status = dtrack_analysis.get("status")
    totals = dtrack_analysis.get("totals") or {}
    trivy_total = vuln_summary.get("total", 0)
    dtrack_total = totals.get("dtrack_vulnerabilities", 0)
    if status == "correlation_gap":
        return f"""
        <section class="panel notice warning">
          <h2>Leitura dos Numeros</h2>
          <p>O relatorio gerencial usa o Trivy central como fonte de vulnerabilidades e encontrou <strong>{esc(trivy_total)}</strong> CVEs. O Dependency-Track recebeu os SBOMs e encontrou <strong>{esc(dtrack_total)}</strong> CVEs correlacionadas nesta execucao. Isso indica lacuna de correlacao no Dependency-Track, nao ausencia de vulnerabilidades nas imagens.</p>
        </section>
        """
    return f"""
    <section class="panel notice">
      <h2>Leitura dos Numeros</h2>
      <p>Trivy central: <strong>{esc(trivy_total)}</strong> CVEs. Dependency-Track correlacionado: <strong>{esc(dtrack_total)}</strong> CVEs. Status: {badge(status)}.</p>
    </section>
    """


def dtrack_project_table(dtrack_analysis, images=None):
    if not dtrack_analysis:
        return '<p class="muted">Sem checagem de correlacao nesta execucao.</p>'
    image_filter = set(images or [])
    rows = []
    for item in dtrack_analysis.get("projects", []) or []:
        if image_filter and item.get("image") not in image_filter:
            continue
        metrics = item.get("metrics") or {}
        rows.append(
            "<tr>"
            f"<td>{esc(item.get('image'))}</td>"
            f"<td>{badge(item.get('status'))}</td>"
            f"<td>{esc(metrics.get('components', 0))}</td>"
            f"<td>{esc(metrics.get('vulnerabilities', 0))}</td>"
            f"<td>{esc(metrics.get('critical', 0))}</td>"
            f"<td>{esc(metrics.get('high', 0))}</td>"
            f"<td>{esc(metrics.get('vulnerableComponents', 0))}</td>"
            "</tr>"
        )
    if not rows:
        return '<p class="muted">Nenhum projeto esperado foi localizado.</p>'
    return f"""
    <div class="table-wrap">
      <table>
        <tr><th>Imagem</th><th>Status</th><th>Componentes</th><th>CVEs DT</th><th>Criticas DT</th><th>Altas DT</th><th>Componentes vulneraveis</th></tr>
        {''.join(rows)}
      </table>
    </div>
    """


def context_table(rows):
    if not rows:
        return '<p class="muted">Sem contextos para classificar nesta execucao.</p>'
    rendered = []
    for row in rows:
        rendered.append(
            "<tr>"
            f"<td>{esc(row.get('context'))}</td>"
            f"<td>{esc(row.get('containers'))}</td>"
            f"<td>{esc(row.get('score_max'))}</td>"
            f"<td>{esc(row.get('score_avg'))}</td>"
            f"<td>{esc(row.get('findings'))}</td>"
            f"<td>{esc(row.get('critical_containers'))}</td>"
            f"<td>{esc(row.get('high_containers'))}</td>"
            "</tr>"
        )
    return (
        "<div class=\"table-wrap\"><table>"
        "<tr><th>Contexto</th><th>Containers</th><th>Score max</th><th>Score medio</th><th>Achados</th><th>Criticos</th><th>Altos</th></tr>"
        f"{''.join(rendered)}</table></div>"
    )


def risk_bars(rows):
    if not rows:
        return '<p class="muted">Sem dados nesta execucao.</p>'
    html_rows = []
    for row in rows:
        score = int(row.get("score", 0) or 0)
        label = f"{row.get('container_name')} ({row.get('host_name')})"
        cls = severity_class(row.get("classification"))
        html_rows.append(
            f"""<div class="bar-row">
              <span>{esc(label)}</span>
              <div class="track"><div class="bar {esc(cls)}" style="width:{score}%"></div></div>
              <strong>{esc(score)}</strong>
            </div>"""
        )
    return f'<div class="risk-bars">{"".join(html_rows)}</div>'


def build_priority_actions(risk_rows, vuln_summary, inventory):
    critical = (vuln_summary.get("severity_counts") or {}).get("CRITICAL", 0)
    high = (vuln_summary.get("severity_counts") or {}).get("HIGH", 0)
    actions = []
    for row in risk_rows:
        score = int(row.get("score", 0) or 0)
        if score >= 81:
            priority = "P1"
            sla = "7 dias"
        elif score >= 61:
            priority = "P2"
            sla = "15 dias"
        elif score >= 31:
            priority = "P3"
            sla = "30 dias"
        else:
            priority = "P4"
            sla = "90 dias"
        actions.append({
            "priority": priority,
            "sla": sla,
            "container": row.get("container_name"),
            "host": row.get("host_name"),
            "image": row.get("image"),
            "score": score,
            "classification": row.get("classification"),
            "action": recommended_action(row),
        })
    if critical or high:
        actions.insert(0, {
            "priority": "P1",
            "sla": "48h a 7 dias",
            "container": "ambiente",
            "host": "todos",
            "image": "imagens com CVEs criticas/altas",
            "score": 100 if critical else 80,
            "classification": "critico" if critical else "alto",
            "action": f"Triar {critical} CVEs criticas e {high} CVEs altas no relatorio Trivy; priorizar componentes com versao corrigida.",
        })
    return actions


def recommended_action(row):
    factors = row.get("factors") or []
    types = {item.get("type") for item in factors}
    if "docker_socket_mounted" in types:
        return "Remover montagem do docker.sock e revisar privilegios do container."
    if "sensitive_host_path_mounted" in types:
        return "Revisar volumes sensiveis e reduzir escopo de montagem."
    if "public_port_exposed" in types:
        return "Restringir exposicao de portas por firewall ou reverse proxy."
    if "latest_tag" in types:
        return "Fixar versao/digest da imagem e criar processo de atualizacao controlado."
    if "running_as_root" in types:
        return "Executar container com usuario nao-root quando a aplicacao permitir."
    if "vulnerability" in types:
        return "Atualizar imagem/base e pacotes vulneraveis conforme relatorio Trivy."
    return "Revisar achados tecnicos e aplicar hardening recomendado."


def priority_list(actions):
    if not actions:
        return '<p class="muted">Sem acoes prioritarias nesta execucao.</p>'
    items = []
    for action in actions:
        items.append(
            f"""<li><strong>{esc(action['priority'])}</strong> - {esc(action['container'])}
            <span class="muted">SLA {esc(action['sla'])}</span><br>{esc(action['action'])}</li>"""
        )
    return f'<ol class="priority">{"".join(items)}</ol>'


def priority_table(actions):
    if not actions:
        return '<p class="muted">Sem acoes prioritarias nesta execucao.</p>'
    rows = []
    for action in actions[:20]:
        rows.append(
            "<tr>"
            f"<td>{badge(action['priority'])}</td>"
            f"<td>{esc(action['sla'])}</td>"
            f"<td>{esc(action['host'])}</td>"
            f"<td>{esc(action['container'])}</td>"
            f"<td>{esc(action['image'])}</td>"
            f"<td>{esc(action['score'])}</td>"
            f"<td>{esc(action['action'])}</td>"
            "</tr>"
        )
    return (
        "<div class=\"table-wrap\"><table>"
        "<tr><th>Prioridade</th><th>SLA</th><th>Host</th><th>Container</th><th>Imagem</th><th>Score</th><th>Acao</th></tr>"
        f"{''.join(rows)}</table></div>"
    )


def top_mitre_tactics(inventory, vuln_summary):
    counts = defaultdict(int)
    for host in inventory.get("hosts", []) or []:
        for finding in host.get("findings", []) or []:
            for tactic in MITRE_BY_FINDING.get(finding.get("type"), []):
                counts[tactic] += 1
    severity = vuln_summary.get("severity_counts") or {}
    if severity.get("CRITICAL", 0) or severity.get("HIGH", 0):
        counts["Initial Access"] += severity.get("CRITICAL", 0) + severity.get("HIGH", 0)
        counts["Execution"] += severity.get("CRITICAL", 0)
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)


def tactic_list(tactics):
    if not tactics:
        return '<p class="muted">Sem correlacao MITRE nesta execucao.</p>'
    rows = [f"<li><strong>{esc(name)}</strong> <span class=\"muted\">{esc(count)} ocorrencias</span></li>" for name, count in tactics]
    return f'<ol class="priority">{"".join(rows)}</ol>'


def trend_chart(rows):
    if not rows:
        return '<p class="muted">Historico insuficiente para tendencia.</p>'
    max_score = max([row.get("max_score", 0) for row in rows] or [1]) or 1
    max_critical = max([row.get("critical", 0) for row in rows] or [1]) or 1
    cards = []
    for row in rows:
        score_h = max(2, round((row.get("max_score", 0) / max_score) * 100))
        critical_h = max(2, round((row.get("critical", 0) / max_critical) * 100)) if row.get("critical", 0) else 0
        cards.append(
            f"""<div class="trend-item">
              <div class="trend-bars">
                <span class="trend-bar score" style="height:{score_h}%"></span>
                <span class="trend-bar critical" style="height:{critical_h}%"></span>
              </div>
              <strong>{esc(row.get('max_score'))}</strong>
              <span>{esc(row.get('critical'))} crit</span>
              <em>{esc(short_run_id(row.get('run_id')))}</em>
            </div>"""
        )
    return (
        '<div class="legend"><span><i class="score"></i>Score maximo</span><span><i class="critical"></i>CVEs criticas</span></div>'
        f'<div class="trend">{"".join(cards)}</div>'
    )


def context_trend_chart(rows):
    if not rows:
        return '<p class="muted">Historico insuficiente para tendencia por contexto.</p>'
    lines = []
    for row in rows:
        contexts = row.get("contexts") or []
        lead = contexts[0] if contexts else {}
        lines.append(
            f"""<div class="trend-item">
              <div class="trend-bars">
                <span class="trend-bar score" style="height:{max(2, min(100, int(lead.get('score_max', 0) or 0)))}%"></span>
                <span class="trend-bar critical" style="height:{max(2, min(100, int(lead.get('critical_containers', 0) or 0) * 12))}%"></span>
              </div>
              <strong>{esc(lead.get('context', 'sem contexto'))}</strong>
              <span>{esc(lead.get('score_max', 0))} max</span>
              <em>{esc(short_run_id(row.get('run_id')))}</em>
            </div>"""
        )
    return (
        '<div class="legend"><span><i class="score"></i>Score maximo do contexto dominante</span><span><i class="critical"></i>Containers criticos</span></div>'
        f'<div class="trend">{"".join(lines)}</div>'
    )


def short_run_id(run_id):
    value = str(run_id or "")
    return value[4:8] + " " + value[9:13] if len(value) >= 13 else value


def wrap_text(text, width=92):
    words = str(text if text is not None else "").replace("\n", " ").split()
    lines = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def pdf_escape(text):
    data = str(text if text is not None else "").encode("latin-1", errors="replace")
    return data.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def write_simple_pdf(path, title, lines):
    page_width = 595
    page_height = 842
    margin_x = 44
    margin_y = 54
    line_height = 14
    max_lines = int((page_height - (margin_y * 2)) / line_height)
    pages = []
    current = []
    for line in lines:
        wrapped = wrap_text(line)
        for part in wrapped:
            if len(current) >= max_lines:
                pages.append(current)
                current = []
            current.append(part)
    if current:
        pages.append(current)
    if not pages:
        pages = [[]]

    objects = []
    catalog_id = 1
    pages_id = 2
    font_id = 3
    page_ids = []
    content_ids = []
    next_id = 4
    for _ in pages:
        page_ids.append(next_id)
        content_ids.append(next_id + 1)
        next_id += 2

    objects.append((catalog_id, b"<< /Type /Catalog /Pages 2 0 R >>"))
    kids = b" ".join([f"{pid} 0 R".encode("ascii") for pid in page_ids])
    objects.append((pages_id, b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(page_ids)).encode("ascii") + b" >>"))
    objects.append((font_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))

    for index, page_lines in enumerate(pages):
        content = bytearray()
        content.extend(b"BT\n/F1 16 Tf\n")
        content.extend(f"{margin_x} {page_height - margin_y} Td\n".encode("ascii"))
        content.extend(b"(" + pdf_escape(title) + b") Tj\n")
        content.extend(b"/F1 10 Tf\n")
        content.extend(f"0 -{line_height * 2} Td\n".encode("ascii"))
        for line in page_lines:
            content.extend(b"(" + pdf_escape(line) + b") Tj\n")
            content.extend(f"0 -{line_height} Td\n".encode("ascii"))
        content.extend(b"ET\n")
        stream = b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + bytes(content) + b"endstream"
        objects.append((content_ids[index], stream))
        page = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 3 0 R >> >> "
            + b"/Contents " + f"{content_ids[index]} 0 R".encode("ascii") + b" >>"
        )
        objects.append((page_ids[index], page))

    objects.sort(key=lambda item: item[0])
    output = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for obj_id, body in objects:
        offsets[obj_id] = len(output)
        output.extend(f"{obj_id} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {max(offsets) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for obj_id in range(1, max(offsets) + 1):
        output.extend(f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii"))
    output.extend(
        b"trailer\n<< /Size " + str(max(offsets) + 1).encode("ascii") + b" /Root 1 0 R >>\nstartxref\n"
        + str(xref).encode("ascii") + b"\n%%EOF\n"
    )
    path.write_bytes(bytes(output))


PDF_COLORS = {
    "text": (31, 41, 51),
    "muted": (100, 116, 139),
    "panel": (255, 255, 255),
    "line": (217, 226, 236),
    "hero": (16, 42, 67),
    "critical": (180, 35, 24),
    "high": (194, 65, 12),
    "medium": (183, 121, 31),
    "low": (47, 133, 90),
    "info": (37, 99, 235),
    "soft": (238, 242, 247),
}


def pdf_rgb(name):
    r, g, b = PDF_COLORS.get(name, PDF_COLORS["text"])
    return f"{r / 255:.3f} {g / 255:.3f} {b / 255:.3f}"


class PdfReport:
    def __init__(self, title):
        self.title = title
        self.width = 842
        self.height = 595
        self.margin = 36
        self.pages = []
        self.content = bytearray()
        self.y = self.margin

    def ensure(self, needed):
        if self.y + needed > self.height - self.margin:
            self.new_page()

    def new_page(self):
        if self.content:
            self.pages.append(bytes(self.content))
        self.content = bytearray()
        self.y = self.margin

    def rect(self, x, y, w, h, color="panel", stroke=None):
        py = self.height - y - h
        self.content.extend(f"{pdf_rgb(color)} rg\n{x:.2f} {py:.2f} {w:.2f} {h:.2f} re f\n".encode("ascii"))
        if stroke:
            self.content.extend(f"{pdf_rgb(stroke)} RG\n{x:.2f} {py:.2f} {w:.2f} {h:.2f} re S\n".encode("ascii"))

    def text(self, x, y, text, size=10, color="text"):
        py = self.height - y
        self.content.extend(b"BT\n")
        self.content.extend(f"/F1 {size} Tf\n{pdf_rgb(color)} rg\n{x:.2f} {py:.2f} Td\n".encode("ascii"))
        self.content.extend(b"(" + pdf_escape(text) + b") Tj\nET\n")

    def wrapped_text(self, x, y, text, width=90, size=10, color="text", line_height=13):
        yy = y
        for line in wrap_text(text, width):
            self.text(x, yy, line, size=size, color=color)
            yy += line_height
        return yy

    def panel_title(self, title):
        self.ensure(34)
        self.text(self.margin, self.y, title, size=14, color="hero")
        self.y += 20

    def bar_chart(self, title, counts, order, color_fn):
        self.panel_title(title)
        max_value = max([int(counts.get(key, 0) or 0) for key in order] or [1]) or 1
        for key in order:
            self.ensure(22)
            value = int(counts.get(key, 0) or 0)
            width = 250 * value / max_value if value else 0
            self.text(self.margin, self.y + 10, key, size=9, color="text")
            self.rect(self.margin + 95, self.y, 250, 12, color="soft")
            if width:
                self.rect(self.margin + 95, self.y, width, 12, color=color_fn(key))
            self.text(self.margin + 355, self.y + 10, value, size=9, color="text")
            self.y += 20
        self.y += 8

    def top_risk_chart(self, rows):
        self.panel_title("Top Containers por Risco")
        for row in rows[:10]:
            self.ensure(24)
            label = f"{row.get('container_name')} ({row.get('context')})"
            score = int(row.get("score", 0) or 0)
            self.text(self.margin, self.y + 10, label[:48], size=9)
            self.rect(self.margin + 235, self.y, 250, 12, color="soft")
            self.rect(self.margin + 235, self.y, max(2, 250 * score / 100), 12, color=severity_class(row.get("classification")))
            self.text(self.margin + 495, self.y + 10, score, size=9)
            self.y += 21
        self.y += 8

    def context_table_pdf(self, rows):
        self.panel_title("Contextos Prioritarios")
        headers = ["Contexto", "Containers", "Score max", "Achados"]
        x_positions = [self.margin, self.margin + 230, self.margin + 310, self.margin + 400]
        for x, header in zip(x_positions, headers):
            self.text(x, self.y, header, size=9, color="muted")
        self.y += 16
        for row in rows[:8]:
            self.ensure(18)
            self.text(x_positions[0], self.y, row.get("context"), size=9)
            self.text(x_positions[1], self.y, row.get("containers"), size=9)
            self.text(x_positions[2], self.y, row.get("score_max"), size=9)
            self.text(x_positions[3], self.y, row.get("findings"), size=9)
            self.y += 16
        self.y += 8

    def trend_chart_pdf(self, rows):
        self.panel_title("Tendencia Historica")
        if not rows:
            self.text(self.margin, self.y, "Historico insuficiente para tendencia.", size=9, color="muted")
            self.y += 20
            return
        max_score = max([int(row.get("max_score", 0) or 0) for row in rows] or [1]) or 1
        max_critical = max([int(row.get("critical", 0) or 0) for row in rows] or [1]) or 1
        base_y = self.y + 110
        x = self.margin
        for row in rows[-8:]:
            score_h = 85 * int(row.get("max_score", 0) or 0) / max_score
            crit_h = 85 * int(row.get("critical", 0) or 0) / max_critical if row.get("critical") else 0
            self.rect(x, base_y - score_h, 16, score_h, color="info")
            if crit_h:
                self.rect(x + 22, base_y - crit_h, 16, crit_h, color="critical")
            self.text(x, base_y + 14, short_run_id(row.get("run_id")), size=8, color="muted")
            x += 82
        self.y = base_y + 34

    def bullet_list(self, title, rows):
        self.panel_title(title)
        for item in rows:
            self.ensure(28)
            self.y = self.wrapped_text(self.margin, self.y, f"- {item}", width=115, size=9)
        self.y += 8

    def save(self, path):
        if self.content:
            self.pages.append(bytes(self.content))
        objects = []
        catalog_id = 1
        pages_id = 2
        font_id = 3
        page_ids = []
        content_ids = []
        next_id = 4
        for _ in self.pages:
            page_ids.append(next_id)
            content_ids.append(next_id + 1)
            next_id += 2
        objects.append((catalog_id, b"<< /Type /Catalog /Pages 2 0 R >>"))
        kids = b" ".join([f"{pid} 0 R".encode("ascii") for pid in page_ids])
        objects.append((pages_id, b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(page_ids)).encode("ascii") + b" >>"))
        objects.append((font_id, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))
        for index, page_content in enumerate(self.pages):
            stream = b"<< /Length " + str(len(page_content)).encode("ascii") + b" >>\nstream\n" + page_content + b"endstream"
            objects.append((content_ids[index], stream))
            page = (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] "
                b"/Resources << /Font << /F1 3 0 R >> >> "
                + b"/Contents " + f"{content_ids[index]} 0 R".encode("ascii") + b" >>"
            )
            objects.append((page_ids[index], page))
        objects.sort(key=lambda item: item[0])
        output = bytearray(b"%PDF-1.4\n")
        offsets = {}
        for obj_id, body in objects:
            offsets[obj_id] = len(output)
            output.extend(f"{obj_id} 0 obj\n".encode("ascii"))
            output.extend(body)
            output.extend(b"\nendobj\n")
        xref = len(output)
        output.extend(f"xref\n0 {max(offsets) + 1}\n".encode("ascii"))
        output.extend(b"0000000000 65535 f \n")
        for obj_id in range(1, max(offsets) + 1):
            output.extend(f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii"))
        output.extend(
            b"trailer\n<< /Size " + str(max(offsets) + 1).encode("ascii") + b" /Root 1 0 R >>\nstartxref\n"
            + str(xref).encode("ascii") + b"\n%%EOF\n"
        )
        path.write_bytes(bytes(output))


def write_executive_pdf(path, run_id, inventory, risk_rows, vuln_summary, dtrack_summary, dtrack_analysis, trivy_summary, trend_rows, context_summary, context_trend):
    summary = inventory.get("summary", {})
    severity_counts = vuln_summary.get("severity_counts") or {}
    finding_severity = summary.get("findings_by_severity") or {}
    dtrack_totals = (dtrack_analysis or {}).get("totals") or {}
    max_score = risk_rows[0]["score"] if risk_rows else 0
    pdf = PdfReport("Relatorio Gerencial - Container Security Monitor")
    pdf.rect(0, 0, pdf.width, 78, color="hero")
    pdf.text(36, 28, "Container Security Monitor", size=10, color="panel")
    pdf.text(36, 52, "Relatorio Gerencial", size=22, color="panel")
    pdf.text(520, 32, f"Risco geral: {classify(max_score).upper()}", size=14, color="panel")
    pdf.text(520, 54, f"score {max_score}/100", size=10, color="panel")
    pdf.y = 104
    kpis = [
        ("Hosts", f"{summary.get('hosts_success', 0)}/{summary.get('hosts_total', 0)}"),
        ("Containers", summary.get("containers_total", 0)),
        ("Imagens", summary.get("images_total", 0)),
        ("Vulnerabilidades", vuln_summary.get("total", 0)),
        ("Criticas", severity_counts.get("CRITICAL", 0)),
        ("Altas", severity_counts.get("HIGH", 0)),
        ("DT CVEs", dtrack_totals.get("dtrack_vulnerabilities", 0)),
    ]
    x = 36
    for label, value in kpis:
        pdf.rect(x, pdf.y, 104, 54, color="panel", stroke="line")
        pdf.text(x + 9, pdf.y + 18, label, size=8, color="muted")
        pdf.text(x + 9, pdf.y + 42, value, size=16, color="text")
        x += 112
    pdf.y += 76
    pdf.bar_chart("Vulnerabilidades por Severidade", severity_counts, SEVERITY_ORDER, severity_class)
    pdf.bar_chart("Achados de Configuracao", finding_severity, FINDING_SEVERITY_ORDER, severity_class)
    pdf.top_risk_chart(risk_rows)
    pdf.context_table_pdf(context_summary)
    pdf.trend_chart_pdf(trend_rows)
    dominant_contexts = []
    for row in context_trend[-6:]:
        contexts = row.get("contexts") or []
        lead = contexts[0] if contexts else {}
        dominant_contexts.append(f"{short_run_id(row.get('run_id'))}: {lead.get('context', 'sem contexto')} score {lead.get('score_max', 0)}")
    pdf.bullet_list("Contexto Dominante em Tendencia", dominant_contexts)
    tactics = [f"{name}: {count} ocorrencias" for name, count in top_mitre_tactics(inventory, vuln_summary)[:6]]
    pdf.bullet_list("MITRE ATT&CK Aproximado", tactics)
    status_lines = [
        f"Inventario: {inventory.get('status')}",
        f"Trivy: {(trivy_summary or {}).get('success', 0)} sucesso / {(trivy_summary or {}).get('failed', 0)} falhas",
        f"Dependency-Track: {(dtrack_summary or {}).get('status')}",
        f"Correlacao DT: {(dtrack_analysis or {}).get('status')}",
        f"SBOMs enviados: {(dtrack_summary or {}).get('uploaded', 0)}",
    ]
    pdf.bullet_list("Status Operacional", status_lines)
    pdf.bullet_list("Prioridade Recomendada", [
        "Tratar containers com score 100 e CVEs criticas.",
        "Substituir tags latest por versoes fixas.",
        "Remover execucao como root quando possivel.",
        "Definir limites de CPU/memoria e healthchecks.",
        "Disponibilizar imagens privadas ao scanner central via registry.",
    ])
    pdf.save(path)


def executive_pdf_lines(run_id, inventory, risk_rows, vuln_summary, dtrack_summary, dtrack_analysis, context_summary):
    summary = inventory.get("summary", {})
    severity_counts = vuln_summary.get("severity_counts") or {}
    dtrack_totals = (dtrack_analysis or {}).get("totals") or {}
    max_score = risk_rows[0]["score"] if risk_rows else 0
    lines = [
        f"Execucao: {run_id}",
        f"Gerado em: {utc_now()}",
        "",
        "Resumo executivo",
        f"Risco geral: {classify(max_score).upper()} - score {max_score}/100",
        f"Hosts analisados: {summary.get('hosts_success', 0)}/{summary.get('hosts_total', 0)}",
        f"Containers inventariados: {summary.get('containers_total', 0)}",
        f"Imagens em uso: {summary.get('images_total', 0)}",
        f"Vulnerabilidades Trivy: {vuln_summary.get('total', 0)}",
        f"Dependency-Track correlacionadas: {dtrack_totals.get('dtrack_vulnerabilities', 0)}",
        "",
        "Vulnerabilidades por severidade",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"- {severity}: {severity_counts.get(severity, 0)}")
    lines.extend(["", "Contextos prioritarios"])
    for row in context_summary[:8]:
        lines.append(
            f"- {row.get('context')}: score max {row.get('score_max')}, containers {row.get('containers')}, achados {row.get('findings')}"
        )
    lines.extend(["", "Top containers por risco"])
    for row in risk_rows[:10]:
        lines.append(
            f"- {row.get('container_name')} ({row.get('context')}): score {row.get('score')}, imagem {row.get('image')}"
        )
    lines.extend([
        "",
        "Prioridade recomendada",
        "1. Tratar containers com score 100 e CVEs criticas.",
        "2. Substituir tags latest por versoes fixas.",
        "3. Remover execucao como root quando possivel.",
        "4. Definir limites de CPU/memoria e healthchecks.",
        "5. Disponibilizar imagens privadas ao scanner central via registry.",
    ])
    return lines


def load_trend(root):
    rows = []
    for path in sorted((root / "output" / "history").glob("risk_scores_*.json")):
        if path.name == "risk_scores_latest.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        scores = data.get("scores", [])
        vuln = data.get("vulnerability_summary", {})
        severity = vuln.get("severity_counts", {})
        rows.append({
            "run_id": data.get("run_id") or path.stem.replace("risk_scores_", ""),
            "max_score": max([item.get("score", 0) for item in scores] or [0]),
            "critical": severity.get("CRITICAL", 0),
            "high": severity.get("HIGH", 0),
            "total": vuln.get("total", 0),
        })
    return rows[-8:]


def main():
    parser = argparse.ArgumentParser(description="Generate backend reports from scan artifacts.")
    parser.add_argument("--root", default=os.environ.get("SECURITY_ROOT", "/opt/security"))
    parser.add_argument("--run-id", default=os.environ.get("RUN_ID") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()

    root = Path(args.root)
    inventory_path = latest(root / "output" / "inventory", "inventory_{run_id}.json", args.run_id)
    findings_path = latest(root / "output" / "reports", "findings_{run_id}.json", args.run_id)
    trivy_path = latest(root / "output" / "trivy", "trivy_summary_{run_id}.json", args.run_id)
    dtrack_path = latest(root / "output" / "dtrack", "dtrack_upload_{run_id}.json", args.run_id)
    dtrack_analysis_path = latest(root / "output" / "dtrack", "dtrack_analysis_{run_id}.json", args.run_id)

    if not inventory_path or not findings_path:
        print("inventory or findings not found; cannot generate reports", file=sys.stderr)
        return 2

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    trivy_summary = json.loads(trivy_path.read_text(encoding="utf-8")) if trivy_path else None
    dtrack_summary = json.loads(dtrack_path.read_text(encoding="utf-8")) if dtrack_path else None
    dtrack_analysis = json.loads(dtrack_analysis_path.read_text(encoding="utf-8")) if dtrack_analysis_path else None
    vuln_summary = load_vulnerabilities(trivy_summary)
    risk_rows = score_findings(findings, inventory=inventory, image_vulns=vuln_summary.get("by_image"))
    trend_rows = load_trend(root)
    context_summary = summarize_context(risk_rows)
    context_trend = load_context_trend(root)
    context_trend.append({
        "run_id": args.run_id,
        "contexts": context_summary,
    })
    context_trend = context_trend[-8:]
    trend_rows.append({
        "run_id": args.run_id,
        "max_score": max([item.get("score", 0) for item in risk_rows] or [0]),
        "critical": (vuln_summary.get("severity_counts") or {}).get("CRITICAL", 0),
        "high": (vuln_summary.get("severity_counts") or {}).get("HIGH", 0),
        "total": vuln_summary.get("total", 0),
    })
    trend_rows = trend_rows[-8:]

    reports_dir = root / "output" / "reports"
    history_dir = root / "output" / "history"
    reports_dir.mkdir(parents=True, exist_ok=True)
    history_dir.mkdir(parents=True, exist_ok=True)

    risk_output = {
        "run_id": args.run_id,
        "generated_at": utc_now(),
        "scores": risk_rows,
        "vulnerability_summary": {
            "total": vuln_summary.get("total", 0),
            "severity_counts": vuln_summary.get("severity_counts", {}),
            "top_vulnerabilities": vuln_summary.get("top_vulnerabilities", [])[:500],
        },
        "context_summary": context_summary,
        "dependency_track_analysis": dtrack_analysis or {},
    }
    risk_path = history_dir / f"risk_scores_{args.run_id}.json"
    technical_path = reports_dir / f"technical_report_{args.run_id}.html"
    executive_path = reports_dir / f"executive_report_{args.run_id}.html"
    executive_pdf_path = reports_dir / f"executive_report_{args.run_id}.pdf"
    actions = build_priority_actions(risk_rows, vuln_summary, inventory)

    risk_path.write_text(json.dumps(risk_output, indent=2, sort_keys=True), encoding="utf-8")
    technical_path.write_text(render_technical(args.run_id, inventory, findings, risk_rows, trivy_summary, vuln_summary, dtrack_summary, dtrack_analysis, context_summary), encoding="utf-8")
    executive_path.write_text(render_executive(args.run_id, inventory, risk_rows, vuln_summary, dtrack_summary, dtrack_analysis, trivy_summary, trend_rows, context_summary, context_trend), encoding="utf-8")
    write_executive_pdf(
        executive_pdf_path,
        args.run_id,
        inventory,
        risk_rows,
        vuln_summary,
        dtrack_summary,
        dtrack_analysis,
        trivy_summary,
        trend_rows,
        context_summary,
        context_trend,
    )

    container_reports_dir = reports_dir / "technical_containers"
    container_reports_dir.mkdir(parents=True, exist_ok=True)
    for row in risk_rows:
        slug = container_slug(row)
        container_path = container_reports_dir / f"{slug}_{args.run_id}.html"
        latest_container_path = container_reports_dir / f"{slug}_latest.html"
        content = render_technical(
            args.run_id,
            inventory,
            findings,
            risk_rows,
            trivy_summary,
            vuln_summary,
            dtrack_summary,
            dtrack_analysis,
            context_summary,
            selected_container=row,
        )
        container_path.write_text(content, encoding="utf-8")
        latest_container_path.write_text(content, encoding="utf-8")

    shutil.copyfile(risk_path, history_dir / "risk_scores_latest.json")
    shutil.copyfile(technical_path, reports_dir / "technical_report_latest.html")
    shutil.copyfile(executive_path, reports_dir / "executive_report_latest.html")
    shutil.copyfile(executive_pdf_path, reports_dir / "executive_report_latest.pdf")
    (reports_dir / "index.html").write_text(render_index(args.run_id, inventory, risk_rows, vuln_summary, dtrack_summary, dtrack_analysis, trend_rows), encoding="utf-8")
    write_priorities(reports_dir / f"priorities_{args.run_id}.csv", actions)
    write_priorities(reports_dir / "priorities_latest.csv", actions)
    (reports_dir / f"priorities_{args.run_id}.json").write_text(json.dumps(actions, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "priorities_latest.json").write_text(json.dumps(actions, indent=2, sort_keys=True), encoding="utf-8")
    return 0


def write_priorities(path, actions):
    fields = ["priority", "sla", "host", "container", "image", "score", "classification", "action"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for action in actions:
            writer.writerow({field: action.get(field) for field in fields})


if __name__ == "__main__":
    sys.exit(main())
