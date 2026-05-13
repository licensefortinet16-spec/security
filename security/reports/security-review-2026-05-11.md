# Security Review - 2026-05-11

## Escopo

Revisao do projeto Container Security Monitor implantado em `200.160.19.14`, com host alvo `200.160.19.2` e raiz operacional local em `/opt/security/security`.

## Correcoes aplicadas

- Atualizadas todas as referencias de `192.168.1.22` para `200.160.19.14`.
- Atualizadas todas as referencias de `192.168.1.30` para `200.160.19.2`.
- Corrigidos defaults e unit files para a raiz real deste clone: `/opt/security/security`.
- Removido `network_mode: host` dos stacks Docker de Dependency-Track, PostgreSQL, Trivy, Prometheus e Grafana.
- PostgreSQL e Trivy deixam de expor portas diretamente no host.
- Dependency-Track frontend/API, Grafana e Prometheus passam a publicar portas explicitamente no IP `200.160.19.14`.
- Substituido token fixo do Trivy por `TRIVY_API_TOKEN` gerado em `dtrack/.env`.
- Prometheus deixou de habilitar `--web.enable-lifecycle`.
- Status server ganhou autenticacao opcional por Basic Auth ou Bearer token, headers de seguranca e suporte a senha via arquivo.
- Instalador do status server cria `/etc/container-security-monitor/status.env` e `/etc/container-security-monitor/status-password` com permissao `0600`.
- Observability local foi removida do repositorio; sobraram apenas metrics textfile e payloads Zabbix opcionais.
- Units systemd receberam hardening basico (`NoNewPrivileges`, `PrivateTmp`, protecoes de kernel/control groups e restricao SUID/SGID).
- Script nftables passou a restringir portas web por `ALLOWED_IPS`, default `200.160.19.2,200.160.19.14,200.160.19.1`.
- Imagens Dependency-Track foram fixadas por digest:
  - `dependencytrack/apiserver@sha256:1ba4f004e1ec4800ec0e0175b0f1cf361a68f6ac3db9274a32d0a47cd4038f51`
  - `dependencytrack/frontend@sha256:00560b57a6cfdec3c02a6e02be80fce97029241a9c653e8b83c0b670dff1f3ca`

## Gaps criticos identificados

- A administracao ainda depende de SSH como `root`. O ideal e usuario dedicado com chave restrita e sudoers minimo para comandos Docker necessarios.
- O status server e Dependency-Track continuam usando HTTP sem TLS. Para acesso fora de rede controlada, usar reverse proxy com TLS e allowlist.
- O scanner executa comandos Docker remotos via SSH. Isso e esperado para o desenho atual, mas equivale a alto privilegio no host alvo.
- Relatorios e SBOMs podem conter nomes de imagens, containers e metadados internos. O acesso aos endpoints de relatorio deve permanecer autenticado e restrito.

## Pendencias operacionais

- Validar manualmente a host key SSH de `200.160.19.2`. O teste local foi bloqueado porque ha uma chave conflitante em `/root/.ssh/known_hosts`.
- Depois de validar a fingerprint, remover a entrada antiga apenas se ela for realmente obsoleta:

```bash
ssh-keygen -f /root/.ssh/known_hosts -R 200.160.19.2
```

- Executar `systemd/apply_network_hardening.sh` para aplicar a allowlist default: `200.160.19.2`, `200.160.19.14` e `200.160.19.1`.
