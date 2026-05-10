# Container Security Monitor

Backend-only security scanner for Docker/OpenPanel environments.

## Current pilot

- Central executor: `192.168.1.22:/opt/security`
- Target host: `192.168.1.30`
- Processing rule: all processing runs only on the central executor.
- Target rule: no agent, Trivy, helper container, scheduled job, cache, report generation or security processing runs on the customer host.

## First commands

Validate dependencies:

```bash
cd /opt/security
./scanner/check_dependencies.sh
```

Install central-server dependencies on Debian:

```bash
cd /opt/security
./scanner/install_central_dependencies.sh
```

Run the current MVP workflow:

```bash
cd /opt/security
./scanner/scan_remote_hosts.sh
```

Inventory only:

```bash
cd /opt/security
python3 ./collectors/docker_inventory.py --root /opt/security
```

Synchronize target images to the central server using `docker save` over SSH:

```bash
cd /opt/security
python3 ./scanner/sync_images_from_targets.py --root /opt/security
```

Status server:

```text
http://192.168.1.22:8090
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

Trivy uses `/opt/security/tmp` and `/opt/security/.cache/trivy` on the central server to avoid filling small `/tmp` tmpfs volumes.

Latest fixed report paths:

```text
/opt/security/output/reports/index.html
/opt/security/output/reports/executive_report_latest.html
/opt/security/output/reports/technical_report_latest.html
/opt/security/output/history/risk_scores_latest.json
```

## Dependency-Track

Create `/opt/security/config/dependency-track.env` from `config/dependency-track.env.example`:

```bash
DTRACK_URL=http://127.0.0.1:8081
DTRACK_API_KEY=replace-with-protected-api-key
```

The scan skips upload safely when this file is absent.

To deploy the local Dependency-Track stack on the central server:

```bash
cd /opt/security
./dtrack/start_dependency_track.sh
./dtrack/status_dependency_track.sh
```

The dev stack binds frontend and API to the central server LAN IP:

- Frontend: `http://192.168.1.22:8080`
- API: `http://192.168.1.22:8081`
- Trivy server for Dependency-Track: `http://127.0.0.1:8082`

If direct frontend access is blocked, use an SSH tunnel from your workstation:

```bash
ssh -L 8080:127.0.0.1:8080 -L 8081:127.0.0.1:8081 -L 8082:127.0.0.1:8082 root@192.168.1.22
```

To let Dependency-Track correlate Trivy SBOMs with its own analyzer, enable the local Trivy server and apply the scanner settings:

```bash
cd /opt/security
./dtrack/configure_trivy_analyzer.sh
```

The helper encrypts the Trivy API token with the Dependency-Track `secret.key` before storing it, so the analyzer can decrypt it safely on startup.

After creating a Dependency-Track API key, write it to `/opt/security/config/dependency-track.env` with mode `600`.

Helper:

```bash
cd /opt/security
./dtrack/configure_api_key.sh 'paste-api-key-here'
```

On first startup, Dependency-Track creates the default `admin` account and requires a password change on first login.

## Weekly timer

Install the weekly systemd timer:

```bash
cd /opt/security
./systemd/install_systemd_timer.sh
```

The timer uses the central server's local timezone. Check it with:

```bash
timedatectl
systemctl list-timers --all | grep container-security
```

Install the status server:

```bash
cd /opt/security
./systemd/install_status_server.sh
```

Install daily retention cleanup:

```bash
cd /opt/security
./systemd/install_cleanup_timer.sh
```

Install daily Dependency-Track database backup:

```bash
cd /opt/security
./systemd/install_dtrack_backup_timer.sh
```

Backups are written to:

```text
/opt/security/output/backups/dependency-track/
```

## Metrics

The scan writes Prometheus textfile and Zabbix sender payloads:

```text
/opt/security/output/metrics/container_security_latest.prom
/opt/security/output/metrics/zabbix_sender_latest.txt
```

Optional Zabbix sending uses `/opt/security/config/zabbix.env`. Start from:

```bash
cp /opt/security/config/zabbix.env.example /opt/security/config/zabbix.env
chmod 600 /opt/security/config/zabbix.env
```

Install the sender only when needed:

```bash
apt-get install -y zabbix-sender
```

Grafana dashboard starter:

```text
/opt/security/integrations/grafana-dashboard-container-security.json
```

Visualização pronta:

```bash
cd /opt/security
./observability/start_observability.sh
```

URLs:

```text
Grafana:    http://192.168.1.22:3000
Prometheus:  http://192.168.1.22:9090
Status UI:   http://192.168.1.22:8090
```

Grafana usa acesso anônimo em modo viewer no ambiente de dev. O dashboard "Container Security Monitor" fica provisionado automaticamente.

Context labels usados no backend:

```text
/opt/security/config/context_aliases.toml
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
/opt/security/config/alert_policy.toml
/opt/security/output/alerts/alerts_latest.json
/opt/security/output/alerts/alerts_latest.prom
```

The rules are evaluated in the backend only. They do not block the scan or the reports; they only mark active conditions for Grafana and metrics consumers.

## Hardening

Restrict project web ports to the LAN only:

```bash
cd /opt/security
LAN_CIDR=192.168.1.0/24 ./systemd/apply_network_hardening.sh
```
