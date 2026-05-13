# Container Security Monitor

Backend-only security scanner for Docker/OpenPanel environments.

## Current pilot

- Central executor: `200.160.19.14:/opt/security/security`
- Target host: `200.160.19.2`
- Processing rule: all processing runs only on the central executor.
- Target rule: no agent, Trivy, helper container, scheduled job, cache, report generation or security processing runs on the customer host.

## First commands

Validate dependencies:

```bash
cd /opt/security/security
./scanner/check_dependencies.sh
```

Install central-server dependencies on Debian:

```bash
cd /opt/security/security
./scanner/install_central_dependencies.sh
```

Run the current MVP workflow:

```bash
cd /opt/security/security
./scanner/scan_remote_hosts.sh
```

Inventory only:

```bash
cd /opt/security/security
python3 ./collectors/docker_inventory.py --root /opt/security/security
```

Synchronize target images to the central server using `docker save` over SSH:

```bash
cd /opt/security/security
python3 ./scanner/sync_images_from_targets.py --root /opt/security/security
```

Code scan only:

```bash
cd /opt/security/security
python3 ./scanner/trivy_code_scan.py --root /opt/security/security
```

The code scan copies each discovered client path to the central server and runs Semgrep plus lightweight PHP checks for source findings. Trivy is limited to `secret,misconfig` in this flow, so dependency CVEs from lockfiles do not populate the code report. Legacy or inactive directories are excluded through `config/code_scan.toml`; the default list includes `_sem-uso`, `site_old`, `old`, backups, logs, caches, `vendor` and `node_modules`.

Status server:

```text
http://200.160.19.14:8090
```

## Outputs

- Inventory JSON/CSV: `output/inventory/`
- Findings JSON/CSV: `output/reports/`
- Trivy JSON: `output/trivy/`
- CycloneDX SBOM: `output/sbom/`
- Image sync logs: `output/image-sync/`
- Dependency-Track uploads: `output/dtrack/`
- Metrics: `output/metrics/`
- History summaries: `output/history/`
- Logs: `output/logs/`

Trivy uses `/opt/security/security/tmp` and `/opt/security/security/.cache/trivy` on the central server to avoid filling small `/tmp` tmpfs volumes.

Latest fixed report paths:

```text
/opt/security/security/output/reports/index.html
/opt/security/security/output/reports/executive_report_latest.html
/opt/security/security/output/reports/executive_report_latest.pdf
/opt/security/security/output/reports/technical_report_latest.html
/opt/security/security/output/reports/technical_containers/<container>_latest.html
/opt/security/security/output/history/risk_scores_latest.json
```

Status server report URLs:

```text
http://200.160.19.14:8090/reports/executive
http://200.160.19.14:8090/reports/executive.pdf
http://200.160.19.14:8090/reports/technical
http://200.160.19.14:8090/reports/technical/containers/<container>
http://200.160.19.14:8090/reports/code
http://200.160.19.14:8090/settings
```

## Dependency-Track

Create `/opt/security/security/config/dependency-track.env` from `config/dependency-track.env.example`:

```bash
DTRACK_URL=http://200.160.19.14:8081
DTRACK_API_KEY=replace-with-protected-api-key
```

The scan skips upload safely when this file is absent.

To deploy the local Dependency-Track stack on the central server:

```bash
cd /opt/security/security
./dtrack/start_dependency_track.sh
./dtrack/status_dependency_track.sh
```

The dev stack binds the Dependency-Track UI to `http://200.160.19.14:8080` through a reverse proxy. API calls are routed through the same origin.
- Frontend/API: `http://200.160.19.14:8080`
- Trivy server for Dependency-Track: `http://trivy:8082` inside the Docker network.

If direct frontend access is blocked, use an SSH tunnel from your workstation:

```bash
ssh -L 8080:127.0.0.1:8080 -L 8082:127.0.0.1:8082 root@200.160.19.14
```

To let Dependency-Track correlate Trivy SBOMs with its own analyzer, enable the local Trivy server and apply the scanner settings:

```bash
cd /opt/security/security
./dtrack/configure_trivy_analyzer.sh
```

The helper encrypts the Trivy API token with the Dependency-Track `secret.key` before storing it, so the analyzer can decrypt it safely on startup.

After creating a Dependency-Track API key, write it to `/opt/security/security/config/dependency-track.env` with mode `600`.

Helper:

```bash
cd /opt/security/security
./dtrack/configure_api_key.sh 'paste-api-key-here'
```

On first startup, Dependency-Track creates the default `admin` account and requires a password change on first login.

## Scheduling scans

The authenticated settings page controls the scan timer:

```text
http://200.160.19.14:8090/settings
```

The page writes `/opt/security/security/config/scan_schedule.json` and updates `/etc/systemd/system/container-security-scan.timer`. It also exposes the SAST exclusion list from `/opt/security/security/config/code_scan.toml` and the tail of the latest scan log. The timer uses the central server's local timezone. The current default is daily at 22:00:

```text
OnCalendar=*-*-* 22:00:00
```

Install or refresh the systemd timer manually when needed:

```bash
cd /opt/security/security
./systemd/install_systemd_timer.sh
```

Check the effective schedule with:

```bash
timedatectl
systemctl list-timers --all | grep container-security
```

Run the unit checks after changing scheduling, reporting or SAST filtering logic:

```bash
cd /opt/security/security
python3 -m unittest discover -s tests
```

Install the status server:

```bash
cd /opt/security/security
./systemd/install_status_server.sh
```

Install daily retention cleanup:

```bash
cd /opt/security/security
./systemd/install_cleanup_timer.sh
```

Install daily Dependency-Track database backup:

```bash
cd /opt/security/security
./systemd/install_dtrack_backup_timer.sh
```

Backups are written to:

```text
/opt/security/security/output/backups/dependency-track/
```

## Metrics

The scan writes metrics and Zabbix sender payloads:

```text
/opt/security/security/output/metrics/container_security_latest.prom
/opt/security/security/output/metrics/zabbix_sender_latest.txt
```

Optional Zabbix sending uses `/opt/security/security/config/zabbix.env`. Start from:

```bash
cp /opt/security/security/config/zabbix.env.example /opt/security/security/config/zabbix.env
chmod 600 /opt/security/security/config/zabbix.env
```

Install the sender only when needed:

```bash
apt-get install -y zabbix-sender
```

Dashboard starter:

```text
/opt/security/security/integrations/grafana-dashboard-container-security.json
```

The local observability stack was removed from this repository. Metrics remain available as textfiles and optional Zabbix payloads.

Context labels usados no backend:

```text
/opt/security/security/config/context_aliases.toml
```

Padrao recomendado para novos stacks:

```text
com.docker.compose.project
com.openpanel.context
context
```

Se nenhum label de contexto existir, o backend classifica como `docker default`.

Alert policy and non-blocking alert export:

```text
/opt/security/security/config/alert_policy.toml
/opt/security/security/output/alerts/alerts_latest.json
/opt/security/security/output/alerts/alerts_latest.prom
```

The rules are evaluated in the backend only. They do not block the scan or the reports; they only mark active conditions for Grafana and metrics consumers.

## Hardening

Restrict project web ports to the approved source IPs only:

```bash
cd /opt/security/security
ALLOWED_IPS=200.160.19.2,200.160.19.14,200.160.19.1,172.30.32.67,200.160.16.18 ./systemd/apply_network_hardening.sh
```
