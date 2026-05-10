# PRD — Container Security Monitor para Docker/OpenPanel

## 1. Visão geral

### 1.1 Nome do projeto

**Container Security Monitor para Docker/OpenPanel**

Nome comercial sugerido:

**Container Risk Intelligence**

### 1.2 Resumo executivo

O projeto tem como objetivo criar uma plataforma centralizada de monitoramento de segurança para containers Docker e ambientes OpenPanel, realizando varreduras remotas semanais, geração de SBOM, análise de vulnerabilidades, envio dos SBOMs para o Dependency-Track, enriquecimento dos riscos com informações de exploração e correlação com MITRE ATT&CK.

A solução deverá gerar dois tipos de relatório:

- **Relatório técnico**, voltado para equipes de infraestrutura, redes, DevOps e segurança.
- **Relatório gerencial**, voltado para coordenação, gestão e diretoria.

Além disso, a plataforma deverá permitir acompanhamento histórico, score de risco, comparação semanal, alertas e integração com Zabbix/Grafana.

### 1.3 Problema a ser resolvido

Ambientes Docker e OpenPanel frequentemente possuem múltiplos containers, imagens antigas, serviços expostos, dependências vulneráveis e configurações inseguras. Sem uma rotina automatizada de análise, os riscos ficam invisíveis até que ocorra um incidente.

Problemas atuais esperados:

- Ausência de inventário centralizado dos containers.
- Falta de visibilidade sobre vulnerabilidades em imagens Docker.
- Ausência de SBOM por aplicação/container.
- Dificuldade para priorizar correções.
- Falta de relatório executivo para gestão.
- Falta de histórico de evolução dos riscos.
- Falta de SLA formal para correção de vulnerabilidades.
- Dificuldade em relacionar vulnerabilidades com táticas e técnicas de ataque.

### 1.4 Objetivo principal

Implantar uma solução automatizada para identificar, classificar, acompanhar e reportar riscos de segurança em containers Docker/OpenPanel, com foco em vulnerabilidades, SBOM, exposição, configuração insegura e priorização de correção.

### 1.5 Resultado esperado

Ao final do projeto, a empresa deverá possuir:

- Scan remoto semanal dos hosts Docker/OpenPanel.
- Inventário atualizado dos containers e imagens.
- SBOM gerado automaticamente por imagem/container.
- Dependency-Track recebendo e analisando os SBOMs.
- Relatórios técnicos e gerenciais automáticos.
- Dashboard operacional no Grafana.
- Alertas no Zabbix ou outro canal definido.
- Score de risco por host, container, imagem e aplicação.
- Correlação básica com MITRE ATT&CK.
- Histórico de evolução semanal.
- Indicadores para demonstrar redução de risco ao longo do tempo.

---

## 2. Justificativa do projeto

### 2.1 Justificativa técnica

Containers podem conter bibliotecas vulneráveis, imagens desatualizadas, pacotes com CVEs críticas e configurações inseguras, como execução com privilégios elevados, uso de `--privileged`, montagem do `docker.sock`, execução como root e exposição indevida de portas.

A solução proposta reduz esse risco por meio de automação, inventário, análise contínua, enriquecimento de dados e geração de relatórios.

### 2.2 Justificativa para gestão

O projeto entrega visibilidade executiva sobre riscos técnicos que normalmente ficam restritos à equipe operacional.

Benefícios para gestão:

- Medição clara do risco do ambiente.
- Priorização baseada em criticidade.
- Indicadores semanais de evolução.
- Redução do risco operacional.
- Apoio a auditorias e conformidade.
- Melhor previsibilidade para correções.
- Evidência de maturidade em segurança.

### 2.3 Valor para o negócio

A plataforma ajuda a evitar:

- Incidentes de segurança.
- Exploração de vulnerabilidades conhecidas.
- Indisponibilidade de serviços.
- Perda de dados.
- Problemas de conformidade.
- Impacto financeiro e reputacional.

Também permite transformar segurança de containers em um processo mensurável.

---

## 3. Escopo

### 3.1 Dentro do escopo

O projeto contempla:

- Descoberta de hosts Docker/OpenPanel cadastrados.
- Conexão remota via SSH.
- Inventário de containers, imagens, portas, volumes e configurações relevantes.
- Scan de vulnerabilidades com Trivy.
- Geração de SBOM no formato CycloneDX.
- Upload automático dos SBOMs para o Dependency-Track.
- Consulta de resultados via API do Dependency-Track.
- Classificação de riscos por severidade.
- Correlação básica com MITRE ATT&CK.
- Cálculo de score de risco.
- Geração de relatório técnico.
- Geração de relatório gerencial.
- Histórico semanal dos resultados.
- Alertas para vulnerabilidades críticas.
- Integração com Zabbix.
- Dashboard no Grafana.
- Agendamento semanal via systemd timer.
- Logs de execução.
- Controle de falhas de scan.

### 3.2 Fora do escopo na primeira versão

Não faz parte do MVP inicial:

- Correção automática de vulnerabilidades.
- Deploy automático de novas imagens.
- Bloqueio automático de containers.
- Runtime protection avançado.
- EDR completo para containers.
- Integração nativa com Kubernetes.
- Análise de código-fonte.
- Gestão completa de secrets.
- Pentest automatizado.
- WAF.

### 3.3 Possíveis expansões futuras

- Integração com Falco para detecção em runtime.
- Integração com Wazuh.
- Integração com CrowdSec.
- Integração com GitLab/GitHub CI/CD.
- Suporte a Kubernetes.
- Abertura automática de chamados.
- Envio de relatórios por e-mail.
- Multi-tenant para atender clientes diferentes.
- Portal web próprio para consulta.
- API própria da solução.

---

## 4. Público-alvo

### 4.1 Usuários técnicos

- Analistas de redes.
- Administradores Linux.
- Equipes de infraestrutura.
- Equipes DevOps.
- Equipes de segurança da informação.
- Responsáveis por Docker/OpenPanel.

### 4.2 Usuários gerenciais

- Coordenadores de TI.
- Gestores de infraestrutura.
- Gestores de segurança.
- Diretoria de tecnologia.
- Responsáveis por risco e conformidade.

---

## 5. Personas

### 5.1 Analista técnico

**Necessidade:** saber exatamente quais containers possuem vulnerabilidades, qual pacote está afetado, qual versão corrigir e qual prioridade seguir.

**Entrega esperada:** relatório técnico detalhado, CSV, JSON e dashboard operacional.

### 5.2 Gestor de TI

**Necessidade:** entender o risco geral do ambiente, evolução semanal e quais aplicações exigem atenção.

**Entrega esperada:** relatório gerencial com gráficos, score, tendência e top riscos.

### 5.3 Responsável por segurança

**Necessidade:** manter evidências de monitoramento contínuo, vulnerabilidades críticas, SLA e exposição do ambiente.

**Entrega esperada:** histórico, trilha de auditoria, matriz de riscos e integração com MITRE ATT&CK.

---

## 6. Objetivos e metas

### 6.1 Objetivos técnicos

- Automatizar o scan semanal dos containers.
- Gerar SBOM para todas as imagens monitoradas.
- Centralizar análise de componentes no Dependency-Track.
- Identificar vulnerabilidades críticas e altas.
- Detectar configurações inseguras em containers.
- Gerar relatórios automáticos.
- Criar histórico comparativo.
- Integrar resultados com Zabbix/Grafana.

### 6.2 Objetivos gerenciais

- Demonstrar maturidade em segurança.
- Reduzir exposição a vulnerabilidades conhecidas.
- Criar indicadores de evolução.
- Apoiar decisões de priorização.
- Justificar investimento em segurança.
- Mostrar valor operacional da equipe.

### 6.3 Metas mensuráveis

| Meta | Indicador | Prazo sugerido |
|---|---:|---:|
| Inventariar containers Docker/OpenPanel | 100% dos hosts cadastrados | MVP |
| Gerar SBOM por imagem | 100% das imagens analisadas | MVP |
| Upload para Dependency-Track | 100% dos SBOMs válidos | MVP |
| Gerar relatório técnico | 1 por execução semanal | MVP |
| Gerar relatório gerencial | 1 por execução semanal | MVP |
| Reduzir vulnerabilidades críticas | 30% em 60 dias | Pós-MVP |
| Criar dashboard Grafana | 1 dashboard principal | Fase 2 |
| Criar alertas Zabbix | Críticas e falhas de scan | Fase 2 |

---

## 7. Requisitos funcionais

### RF01 — Cadastro de hosts monitorados

A solução deverá permitir cadastrar hosts Docker/OpenPanel em um arquivo de configuração.

Exemplo:

```yaml
hosts:
  - name: docker01
    ip: 192.168.10.20
    ssh_user: root
    environment: producao
    criticality: alta
    openpanel: true

  - name: docker02
    ip: 192.168.10.21
    ssh_user: root
    environment: homologacao
    criticality: media
    openpanel: false
```

Critérios de aceite:

- Deve permitir múltiplos hosts.
- Deve permitir classificar ambiente.
- Deve permitir definir criticidade.
- Deve suportar autenticação via chave SSH.

---

### RF02 — Inventário remoto de containers

A solução deverá se conectar aos hosts remotos e coletar:

- Nome do host.
- IP do host.
- Lista de containers.
- ID do container.
- Nome do container.
- Imagem utilizada.
- Tag da imagem.
- Status do container.
- Portas expostas.
- Volumes montados.
- Networks utilizadas.
- Labels.
- Data de criação.
- Comando de inicialização.
- Usuário configurado no container.

Critérios de aceite:

- Deve gerar inventário em JSON.
- Deve gerar inventário em CSV.
- Deve registrar containers parados e em execução.
- Deve identificar containers relacionados ao OpenPanel.

---

### RF03 — Identificação de configurações inseguras

A solução deverá verificar configurações de risco, incluindo:

- Container privilegiado.
- Uso de `--net=host`.
- Uso de `--pid=host`.
- Montagem de `/var/run/docker.sock`.
- Montagem de diretórios sensíveis.
- Execução como root.
- Ausência de healthcheck.
- Uso de tag `latest`.
- Capabilities perigosas.
- Portas expostas publicamente.
- Ausência de limite de CPU/memória.

Critérios de aceite:

- Deve gerar lista de achados por container.
- Deve classificar os achados por criticidade.
- Deve incluir recomendações técnicas.

---

### RF04 — Scan de vulnerabilidades com Trivy

A solução deverá executar o Trivy para analisar imagens de containers.

Tipos mínimos de análise:

- Vulnerabilidades de pacotes do sistema.
- Vulnerabilidades de bibliotecas de aplicação.
- Severidade por CVE.
- Pacote afetado.
- Versão instalada.
- Versão corrigida, quando disponível.

Critérios de aceite:

- Deve gerar saída em JSON.
- Deve gerar resultado por imagem.
- Deve suportar imagens públicas e privadas.
- Deve registrar falhas de scan.
- Deve evitar duplicidade desnecessária para a mesma imagem/tag.

---

### RF05 — Geração de SBOM

A solução deverá gerar SBOM em formato CycloneDX para cada imagem analisada.

Critérios de aceite:

- Deve gerar arquivo `.json` por imagem.
- Deve armazenar SBOM com nome padronizado.
- Deve associar SBOM ao host/container de origem.
- Deve validar se o arquivo foi gerado com sucesso.

Exemplo de nomenclatura:

```text
sbom_docker01_openpanel-web_2026-05-09.json
```

---

### RF06 — Upload para Dependency-Track

A solução deverá enviar automaticamente os SBOMs para o Dependency-Track via API.

Critérios de aceite:

- Deve criar ou atualizar projetos no Dependency-Track.
- Deve associar cada SBOM ao projeto correto.
- Deve registrar sucesso/falha do upload.
- Deve armazenar o UUID do projeto.
- Deve permitir configurar URL e API Key por arquivo `.env`.

Exemplo de variáveis:

```env
DTRACK_URL=http://dependency-track.local
DTRACK_API_KEY=xxxxxxxxxxxxxxxx
```

---

### RF07 — Consulta de resultados no Dependency-Track

A solução deverá consultar dados do Dependency-Track após o envio dos SBOMs.

Dados desejados:

- Total de vulnerabilidades.
- Vulnerabilidades por severidade.
- Componentes vulneráveis.
- Projetos com maior risco.
- Vulnerabilidades auditadas.
- Vulnerabilidades suprimidas.
- Componentes desatualizados.

Critérios de aceite:

- Deve consultar a API do Dependency-Track.
- Deve consolidar dados para relatório.
- Deve tratar indisponibilidade da API.

---

### RF08 — Enriquecimento com MITRE ATT&CK

A solução deverá relacionar vulnerabilidades e achados com táticas e técnicas MITRE ATT&CK prováveis.

Exemplos:

| Tipo de achado | Tática MITRE provável |
|---|---|
| RCE | Initial Access / Execution |
| Escalação de privilégio | Privilege Escalation |
| Vazamento de credenciais | Credential Access |
| Docker socket montado | Privilege Escalation / Defense Evasion |
| Container privilegiado | Privilege Escalation |
| SSRF | Initial Access / Discovery |
| Path Traversal | Collection / Defense Evasion |

Critérios de aceite:

- Deve indicar que o mapeamento é aproximado.
- Deve apresentar táticas mais recorrentes no relatório.
- Deve permitir atualização futura da matriz de correlação.

---

### RF09 — Score de risco

A solução deverá calcular score de risco por:

- Container.
- Imagem.
- Host.
- Aplicação/projeto.

Modelo inicial sugerido:

| Fator | Peso |
|---|---:|
| CVE crítica | +30 |
| CVE alta | +15 |
| Exploit conhecido | +25 |
| Exposição à internet | +20 |
| Container privilegiado | +20 |
| Docker socket montado | +25 |
| Execução como root | +10 |
| Imagem com tag latest | +5 |
| Imagem antiga | +10 |
| Sem correção disponível | +5 |

Classificação:

| Score | Classificação |
|---:|---|
| 0 a 30 | Baixo |
| 31 a 60 | Médio |
| 61 a 80 | Alto |
| 81 a 100 | Crítico |

Critérios de aceite:

- Score máximo deve ser limitado a 100.
- Deve ser possível ajustar pesos por arquivo de configuração.
- Deve aparecer no relatório técnico e gerencial.

---

### RF10 — Relatório técnico

A solução deverá gerar relatório técnico detalhado em HTML e PDF.

Conteúdo mínimo:

- Data da execução.
- Hosts analisados.
- Containers analisados.
- Imagens analisadas.
- SBOMs gerados.
- Falhas de scan.
- Vulnerabilidades por severidade.
- Lista de CVEs.
- Pacote afetado.
- Versão instalada.
- Versão corrigida.
- Container afetado.
- Host afetado.
- Link de referência.
- Score de risco.
- Configurações inseguras.
- Recomendações técnicas.
- SLA sugerido.

Critérios de aceite:

- Deve ser gerado automaticamente a cada execução.
- Deve conter dados suficientes para correção.
- Deve permitir exportação em CSV/JSON.

---

### RF11 — Relatório gerencial

A solução deverá gerar relatório gerencial em HTML e PDF.

Conteúdo mínimo:

- Resumo executivo.
- Nível geral de risco.
- Quantidade de hosts analisados.
- Quantidade de containers analisados.
- Quantidade de riscos críticos, altos, médios e baixos.
- Top 5 aplicações/containers mais críticos.
- Evolução em relação à semana anterior.
- Gráfico de tendência.
- Riscos vencidos por SLA.
- Principais recomendações.
- Status geral: melhorou, piorou ou estável.

Exemplo de texto gerencial esperado:

```text
Foram analisados 32 containers em 4 hosts Docker/OpenPanel.
O ambiente apresenta risco ALTO devido à presença de 6 vulnerabilidades críticas, sendo 2 associadas a componentes com alto impacto potencial.
Comparado à semana anterior, houve redução de 18% nas vulnerabilidades críticas.
```

Critérios de aceite:

- Deve ser compreensível para não técnicos.
- Deve evitar excesso de CVEs no corpo principal.
- Deve destacar impacto e prioridade.
- Deve ser adequado para apresentação à gestão.

---

### RF12 — Histórico semanal

A solução deverá manter histórico dos scans.

Dados históricos:

- Data da execução.
- Total de containers.
- Total de vulnerabilidades.
- Vulnerabilidades por severidade.
- Score por host.
- Score por aplicação.
- Quantidade de falhas.
- Comparativo com execução anterior.

Critérios de aceite:

- Deve permitir comparação semanal.
- Deve armazenar dados em JSON, CSV ou banco local.
- Deve alimentar relatório gerencial.

---

### RF13 — Alertas

A solução deverá gerar alertas para eventos críticos.

Eventos mínimos:

- CVE crítica detectada.
- CVE crítica com exploit conhecido.
- Container privilegiado detectado.
- Docker socket montado em container.
- Falha no scan de host.
- Dependency-Track indisponível.
- Score de risco acima de 80.

Canais possíveis:

- Zabbix.
- E-mail.
- Telegram.
- Webhook.
- Grafana Alerting.

Critérios de aceite:

- Deve enviar alerta pelo menos para Zabbix no MVP estendido.
- Deve evitar alertas duplicados excessivos.
- Deve registrar alertas enviados.

---

### RF14 — Integração com Zabbix

A solução deverá enviar métricas para o Zabbix via `zabbix_sender` ou API.

Itens sugeridos:

```text
container.security.total_containers
container.security.total_images
container.security.critical_vulns
container.security.high_vulns
container.security.medium_vulns
container.security.low_vulns
container.security.risk_score
container.security.last_scan_status
container.security.failed_scans
container.security.privileged_containers
container.security.docker_socket_mounts
```

Triggers sugeridas:

```text
Critical vulnerabilities > 0
Risk score > 80
Scan failed
Dependency-Track unavailable
Privileged container detected
Docker socket mounted
```

Critérios de aceite:

- Deve enviar métricas após cada scan.
- Deve permitir criar triggers no Zabbix.
- Deve registrar sucesso/falha no envio.

---

### RF15 — Dashboard Grafana

A solução deverá disponibilizar dados para dashboard Grafana.

Painéis recomendados:

- Total de containers monitorados.
- Vulnerabilidades por severidade.
- Evolução semanal de críticas/altas.
- Score médio do ambiente.
- Top hosts por risco.
- Top containers por risco.
- Falhas de scan.
- Containers privilegiados.
- Containers com Docker socket.
- SLA vencido.

Critérios de aceite:

- Deve haver pelo menos um dashboard principal.
- Deve permitir visão operacional e gerencial.
- Deve usar fonte de dados compatível, como Prometheus, VictoriaMetrics, InfluxDB ou PostgreSQL.

---

## 8. Requisitos não funcionais

### RNF01 — Segurança de acesso

- Conexão remota deve usar SSH com chave.
- A chave SSH deve ter permissão mínima necessária.
- API Key do Dependency-Track deve ficar em arquivo protegido.
- Arquivos `.env` não devem ser versionados.
- Logs não devem expor secrets.

### RNF02 — Confiabilidade

- Falha em um host não deve interromper toda a execução.
- Cada erro deve ser registrado.
- O relatório deve informar hosts com falha.
- Deve existir código de saída compatível com monitoramento.

### RNF03 — Desempenho

- A solução deve evitar scan duplicado da mesma imagem no mesmo ciclo.
- Deve permitir execução paralela controlada.
- Deve ter timeout por host.
- Deve permitir limitar consumo de CPU/memória.

### RNF04 — Manutenibilidade

- Scripts devem ser organizados por função.
- Configurações devem ficar fora do código.
- Logs devem ser padronizados.
- O projeto deve possuir documentação de instalação e operação.

### RNF05 — Portabilidade

- A solução deve rodar em Linux.
- Preferencialmente em Debian/Ubuntu.
- Componentes principais devem rodar em Docker Compose.
- Scripts devem usar Bash e Python.

### RNF06 — Auditoria

- Cada execução deve gerar logs.
- Cada relatório deve ter data/hora.
- Cada SBOM deve ser armazenado com referência ao scan.
- O histórico deve permitir comparação entre períodos.

---

## 9. Arquitetura proposta

### 9.1 Visão lógica

```text
+-----------------------------+
| Servidor Central             |
| Container Security Monitor   |
+-------------+---------------+
              |
              | SSH
              v
+-----------------------------+
| Hosts Docker/OpenPanel       |
| docker01, docker02, etc.     |
+-------------+---------------+
              |
              | Inventário + imagens
              v
+-----------------------------+
| Trivy                        |
| Scan + SBOM CycloneDX        |
+-------------+---------------+
              |
              | Upload SBOM
              v
+-----------------------------+
| Dependency-Track             |
| Análise de componentes       |
+-------------+---------------+
              |
              | API
              v
+-----------------------------+
| Engine de relatório          |
| Técnico + Gerencial          |
+-------------+---------------+
              |
              v
+-----------------------------+
| Zabbix / Grafana / Alertas   |
+-----------------------------+
```

### 9.2 Componentes

| Componente | Função |
|---|---|
| Trivy | Scan de vulnerabilidades e geração de SBOM |
| Dependency-Track | Gestão e análise de SBOM |
| PostgreSQL | Banco do Dependency-Track |
| Bash | Orquestração dos scans |
| Python | Consolidação, enriquecimento e relatórios |
| Jinja2 | Templates HTML |
| WeasyPrint/wkhtmltopdf | Conversão HTML para PDF |
| Zabbix | Alertas operacionais |
| Grafana | Dashboards |
| systemd timer | Agendamento semanal |

### 9.3 Estrutura de diretórios

```text
/opt/container-security-monitor/
├── scanner/
│   ├── scan_remote_hosts.sh
│   ├── inventory.sh
│   ├── trivy_scan.sh
│   ├── generate_sbom.sh
│   ├── upload_sbom_dependency_track.sh
│   └── docker_config_checks.sh
├── enrichment/
│   ├── mitre_mapping.py
│   ├── risk_score.py
│   └── exploit_enrichment.py
├── reports/
│   ├── technical_report.py
│   ├── executive_report.py
│   └── templates/
├── integrations/
│   ├── zabbix_sender.sh
│   ├── grafana_metrics.py
│   └── webhook_alert.py
├── config/
│   ├── hosts.yml
│   ├── dependency-track.env
│   ├── severity_policy.yml
│   └── mitre_mapping.yml
├── output/
│   ├── inventory/
│   ├── trivy/
│   ├── sbom/
│   ├── reports/
│   ├── history/
│   └── logs/
├── systemd/
│   ├── container-security-scan.service
│   └── container-security-scan.timer
├── docker-compose.yml
└── README.md
```

---

## 10. Fluxo de execução

### 10.1 Fluxo semanal

1. systemd timer inicia a execução.
2. Script principal carrega `hosts.yml`.
3. Para cada host:
   - testa conectividade SSH;
   - coleta inventário Docker;
   - identifica containers OpenPanel;
   - coleta imagens usadas;
   - verifica configurações inseguras;
   - executa scan Trivy;
   - gera SBOM CycloneDX;
   - salva JSON técnico.
4. SBOMs são enviados ao Dependency-Track.
5. API do Dependency-Track é consultada.
6. Engine calcula score de risco.
7. Engine faz correlação MITRE.
8. Histórico é atualizado.
9. Relatórios são gerados.
10. Métricas são enviadas ao Zabbix/Grafana.
11. Alertas são enviados, se necessário.

### 10.2 Fluxo de priorização

Ordem sugerida de prioridade:

1. CVEs críticas com exploit conhecido.
2. CVEs críticas em container exposto à internet.
3. Docker socket montado.
4. Container privilegiado.
5. CVEs altas em serviço crítico.
6. Imagens sem atualização há muito tempo.
7. Configurações inseguras de menor impacto.

---

## 11. Política de severidade e SLA

### 11.1 Severidade

| Severidade | Descrição |
|---|---|
| Crítica | Pode permitir comprometimento grave, RCE, escalação ou exploração relevante |
| Alta | Pode causar impacto significativo ou facilitar ataque |
| Média | Requer condição específica ou impacto limitado |
| Baixa | Baixo impacto ou exploração improvável |
| Informativa | Recomendação ou melhoria de postura |

### 11.2 SLA sugerido

| Tipo de risco | Prazo de correção |
|---|---:|
| Crítica com exploit conhecido | 48 horas |
| Crítica sem exploit conhecido | 7 dias |
| Alta | 15 dias |
| Média | 30 dias |
| Baixa | 90 dias |
| Configuração insegura crítica | 7 dias |

### 11.3 Status de SLA

| Status | Descrição |
|---|---|
| Dentro do prazo | Ainda dentro do SLA |
| Vencendo | Próximo do prazo limite |
| Vencido | Prazo ultrapassado |
| Corrigido | Vulnerabilidade não aparece mais |
| Aceito | Risco aceito formalmente |

---

## 12. Relatórios

### 12.1 Relatório técnico

Formato:

- HTML.
- PDF.
- CSV.
- JSON.

Seções:

1. Identificação do relatório.
2. Resumo da execução.
3. Hosts analisados.
4. Containers analisados.
5. Imagens analisadas.
6. Vulnerabilidades por severidade.
7. Vulnerabilidades detalhadas.
8. Configurações inseguras.
9. SBOMs gerados.
10. Resultados do Dependency-Track.
11. Correlação MITRE.
12. Score de risco.
13. Recomendações técnicas.
14. SLA.
15. Anexos.

### 12.2 Relatório gerencial

Formato:

- HTML.
- PDF.

Seções:

1. Resumo executivo.
2. Nível geral de risco.
3. Evolução semanal.
4. Principais riscos.
5. Top 5 containers críticos.
6. Top 5 hosts críticos.
7. Indicadores de SLA.
8. Impacto para o negócio.
9. Ações recomendadas.
10. Conclusão.

### 12.3 Exemplo de indicadores gerenciais

| Indicador | Valor |
|---|---:|
| Hosts analisados | 4 |
| Containers analisados | 32 |
| Imagens únicas | 18 |
| Vulnerabilidades críticas | 6 |
| Vulnerabilidades altas | 28 |
| Score geral | 78 |
| Risco geral | Alto |
| Redução semanal de críticas | 18% |
| Containers com configuração insegura | 5 |
| Falhas de scan | 1 |

---

## 13. Dashboard Grafana

### 13.1 Dashboard principal

Nome sugerido:

**Container Security Overview**

Painéis:

- Score geral do ambiente.
- Vulnerabilidades por severidade.
- Evolução semanal de críticas e altas.
- Top 10 containers por risco.
- Top 10 hosts por risco.
- Containers privilegiados.
- Containers com Docker socket.
- Falhas de scan.
- SLA vencido.
- Quantidade de SBOMs enviados ao Dependency-Track.

### 13.2 Dashboard técnico

Nome sugerido:

**Container Technical Risk Details**

Painéis:

- CVEs por imagem.
- Pacotes mais vulneráveis.
- Imagens mais antigas.
- Containers com `latest`.
- Containers rodando como root.
- Portas expostas.
- Volumes sensíveis.

---

## 14. Integração com MITRE ATT&CK

### 14.1 Objetivo

Adicionar contexto ofensivo aos riscos encontrados, ajudando a demonstrar como determinados achados poderiam ser aproveitados em uma cadeia de ataque.

### 14.2 Modelo inicial

Arquivo `mitre_mapping.yml`:

```yaml
rules:
  - condition: "rce"
    tactics:
      - Initial Access
      - Execution

  - condition: "privilege_escalation"
    tactics:
      - Privilege Escalation

  - condition: "credential_disclosure"
    tactics:
      - Credential Access

  - condition: "docker_socket_mounted"
    tactics:
      - Privilege Escalation
      - Defense Evasion

  - condition: "privileged_container"
    tactics:
      - Privilege Escalation
      - Defense Evasion
```

### 14.3 Saída esperada

Exemplo:

```text
As principais táticas MITRE associadas aos riscos encontrados foram:

1. Privilege Escalation
2. Initial Access
3. Execution
4. Credential Access
5. Defense Evasion
```

### 14.4 Observação importante

O mapeamento MITRE deve ser apresentado como correlação aproximada e contextual, não como verdade absoluta para cada CVE.

---

## 15. Segurança da própria solução

### 15.1 Riscos da solução

A plataforma terá acesso remoto aos hosts Docker, portanto deve ser protegida.

Riscos principais:

- Vazamento de chave SSH.
- Vazamento da API Key do Dependency-Track.
- Exposição indevida do painel Dependency-Track.
- Relatórios contendo informações sensíveis.
- Logs com dados internos.

### 15.2 Controles obrigatórios

- Usar SSH por chave.
- Proteger chave com permissão `600`.
- Restringir origem no firewall.
- Rodar a solução em servidor dedicado.
- Usar HTTPS no Dependency-Track.
- Proteger API Key em `.env`.
- Fazer backup do banco PostgreSQL.
- Controlar acesso aos relatórios.
- Não expor relatórios publicamente.
- Separar usuário operacional se possível.

### 15.3 Hardening recomendado

- Firewall local ativo.
- Fail2ban ou CrowdSec.
- Acesso administrativo restrito.
- Backup criptografado.
- Logs rotacionados.
- Atualização periódica do Trivy.
- Atualização periódica do Dependency-Track.

---

## 16. Dados e armazenamento

### 16.1 Dados coletados

- Informações de hosts.
- Informações de containers.
- Informações de imagens.
- Vulnerabilidades.
- SBOMs.
- Configurações inseguras.
- Score de risco.
- Histórico semanal.
- Logs de execução.

### 16.2 Retenção sugerida

| Tipo de dado | Retenção |
|---|---:|
| Logs detalhados | 90 dias |
| Relatórios PDF | 12 meses |
| SBOMs | 12 meses |
| Histórico consolidado | 24 meses |
| JSON bruto de scan | 6 meses |

### 16.3 Backup

Itens obrigatórios no backup:

- Banco PostgreSQL do Dependency-Track.
- Diretório `/opt/container-security-monitor/config`.
- Diretório de relatórios.
- Diretório de histórico.
- Templates de relatório.

---

## 17. Agendamento

### 17.1 Frequência

Execução semanal.

Sugestão:

```text
Domingo às 02:00
```

### 17.2 systemd service

Arquivo:

```text
/etc/systemd/system/container-security-scan.service
```

Função:

- Executar script principal.
- Registrar logs no journal.
- Retornar status de sucesso ou falha.

### 17.3 systemd timer

Arquivo:

```text
/etc/systemd/system/container-security-scan.timer
```

Função:

- Agendar execução semanal.
- Permitir consulta via `systemctl list-timers`.

---

## 18. Roadmap

### 18.1 Fase 0 — Preparação

Duração estimada: 1 semana.

Entregas:

- Definir servidor central.
- Instalar Docker/Docker Compose.
- Subir Dependency-Track.
- Instalar Trivy.
- Criar estrutura inicial do projeto.
- Definir hosts piloto.

Critérios de aceite:

- Dependency-Track acessível.
- Trivy funcional.
- Host piloto acessível por SSH.

---

### 18.2 Fase 1 — MVP técnico

Duração estimada: 2 a 3 semanas.

Entregas:

- Inventário remoto.
- Scan com Trivy.
- Geração de SBOM.
- Upload para Dependency-Track.
- Relatório técnico simples.
- Log de execução.

Critérios de aceite:

- Pelo menos 1 host analisado ponta a ponta.
- SBOM aparece no Dependency-Track.
- Relatório técnico é gerado.

---

### 18.3 Fase 2 — Gestão e histórico

Duração estimada: 2 semanas.

Entregas:

- Relatório gerencial.
- Histórico semanal.
- Comparativo com semana anterior.
- Score de risco.
- Exportação CSV.

Critérios de aceite:

- Relatório gerencial apresenta risco geral.
- Histórico permite comparação.
- Score é calculado por host/container.

---

### 18.4 Fase 3 — Zabbix e Grafana

Duração estimada: 2 semanas.

Entregas:

- Métricas para Zabbix.
- Triggers principais.
- Dashboard Grafana.
- Alertas para riscos críticos.

Critérios de aceite:

- Zabbix recebe métricas.
- Grafana exibe dashboard.
- Alerta é disparado para CVE crítica ou falha de scan.

---

### 18.5 Fase 4 — MITRE e maturidade

Duração estimada: 2 semanas.

Entregas:

- Correlação MITRE.
- Melhorias no relatório executivo.
- Matriz de táticas mais recorrentes.
- Política de SLA.
- Recomendações por tipo de risco.

Critérios de aceite:

- Relatórios exibem táticas MITRE prováveis.
- SLA aparece por vulnerabilidade crítica/alta.
- Gestão consegue visualizar evolução de risco.

---

## 19. Critérios gerais de aceite

O projeto será considerado entregue quando:

- A solução executar scan semanal automaticamente.
- Conseguir analisar hosts Docker/OpenPanel remotamente.
- Gerar inventário dos containers.
- Gerar SBOM por imagem.
- Enviar SBOMs para o Dependency-Track.
- Gerar relatório técnico.
- Gerar relatório gerencial.
- Calcular score de risco.
- Manter histórico semanal.
- Integrar pelo menos com Zabbix ou Grafana.
- Registrar falhas de execução.
- Possuir documentação de instalação e operação.

---

## 20. Indicadores de sucesso

### 20.1 Indicadores técnicos

| Indicador | Meta |
|---|---:|
| Hosts monitorados | 100% dos hosts definidos |
| Containers inventariados | 100% dos containers encontrados |
| SBOMs gerados | 100% das imagens únicas |
| Uploads bem-sucedidos | > 95% |
| Falhas de scan | < 5% |
| Relatórios gerados | 100% das execuções |

### 20.2 Indicadores de segurança

| Indicador | Meta |
|---|---:|
| Redução de CVEs críticas | 30% em 60 dias |
| Redução de containers privilegiados | 50% em 90 dias |
| Redução de imagens com `latest` | 80% em 90 dias |
| Vulnerabilidades críticas dentro do SLA | > 90% |

### 20.3 Indicadores gerenciais

| Indicador | Meta |
|---|---:|
| Relatório executivo semanal | 1 por semana |
| Dashboard atualizado | Após cada scan |
| Tendência de risco | Redução contínua |
| Evidência de melhoria | Mensal |

---

## 21. Riscos do projeto

| Risco | Impacto | Mitigação |
|---|---|---|
| Falha de acesso SSH | Host sem scan | Validar chave e conectividade antes da execução |
| Imagem privada sem acesso | Scan incompleto | Configurar autenticação no registry |
| Dependency-Track indisponível | SBOM não enviado | Reprocessar uploads pendentes |
| Muitos falsos positivos | Perda de confiança | Criar processo de triagem e supressão controlada |
| Relatório complexo demais | Gestão não usa | Criar versão gerencial resumida |
| Consumo alto de recurso | Impacto na máquina central | Limitar paralelismo e agendar fora do horário comercial |
| Vazamento de credenciais | Alto risco | Proteger arquivos, chaves e permissões |

---

## 22. Dependências

### 22.1 Técnicas

- Servidor Linux para centralizar a solução.
- Docker e Docker Compose.
- Acesso SSH aos hosts Docker/OpenPanel.
- Permissão para executar comandos Docker remotamente.
- Trivy instalado.
- Dependency-Track disponível.
- PostgreSQL para Dependency-Track.
- Python 3.
- Bibliotecas Python necessárias.
- Zabbix/Grafana, se aplicável.

### 22.2 Organizacionais

- Aprovação para monitorar hosts.
- Definição de responsáveis por correção.
- Definição de SLA.
- Definição de criticidade dos ambientes.
- Apoio da gestão para tratamento dos achados.

---

## 23. Requisitos de documentação

A documentação do projeto deverá conter:

- Visão geral.
- Diagrama de arquitetura.
- Guia de instalação.
- Guia de configuração.
- Como cadastrar hosts.
- Como executar scan manual.
- Como consultar logs.
- Como acessar relatórios.
- Como interpretar score.
- Como operar Dependency-Track.
- Como configurar Zabbix.
- Como configurar Grafana.
- Procedimento de backup.
- Procedimento de atualização.
- Troubleshooting.

---

## 24. Comandos operacionais esperados

### 24.1 Executar scan manual

```bash
cd /opt/container-security-monitor
sudo ./scanner/scan_remote_hosts.sh
```

### 24.2 Ver logs do systemd

```bash
journalctl -u container-security-scan.service -n 100 --no-pager
```

### 24.3 Ver timers

```bash
systemctl list-timers | grep container-security
```

### 24.4 Testar conectividade com host

```bash
ssh root@docker01 "docker ps"
```

### 24.5 Ver relatórios

```bash
ls -lh /opt/container-security-monitor/output/reports/
```

---

## 25. Configuração inicial sugerida

### 25.1 Arquivo `hosts.yml`

```yaml
hosts:
  - name: openpanel01
    ip: 192.168.10.10
    ssh_user: root
    environment: producao
    criticality: alta
    openpanel: true
    internet_exposed: true

  - name: docker02
    ip: 192.168.10.11
    ssh_user: root
    environment: homologacao
    criticality: media
    openpanel: false
    internet_exposed: false
```

### 25.2 Arquivo `severity_policy.yml`

```yaml
sla:
  critical_with_exploit_hours: 48
  critical_days: 7
  high_days: 15
  medium_days: 30
  low_days: 90

risk_score:
  critical_cve: 30
  high_cve: 15
  known_exploit: 25
  internet_exposed: 20
  privileged_container: 20
  docker_socket_mounted: 25
  running_as_root: 10
  latest_tag: 5
  old_image: 10
```

---

## 26. MVP mínimo recomendado

Para uma primeira entrega com valor real, o MVP deve conter:

1. Dependency-Track rodando.
2. Trivy instalado.
3. Arquivo de hosts.
4. Scan remoto via SSH.
5. Inventário de containers.
6. Geração de SBOM CycloneDX.
7. Upload para Dependency-Track.
8. Relatório técnico em HTML/PDF.
9. Relatório gerencial simples.
10. Histórico semanal básico.

Esse MVP já é suficiente para apresentar valor para gestão.

---

## 27. Versão vendável do projeto

### 27.1 Posicionamento

A solução pode ser apresentada como:

> Plataforma automatizada de gestão de risco em containers Docker/OpenPanel com SBOM, análise de vulnerabilidades, score de risco, MITRE ATT&CK, relatórios executivos e integração com monitoramento.

### 27.2 Diferenciais

- Sem necessidade de agente pesado nos hosts.
- Scan remoto centralizado.
- Geração automática de SBOM.
- Integração com Dependency-Track.
- Relatório técnico e gerencial.
- Score próprio de risco.
- Integração com Zabbix e Grafana.
- Visão por host, container, imagem e aplicação.
- Histórico de evolução semanal.
- Adequado para empresas pequenas e médias.

### 27.3 Argumento para aumento de salário

Este projeto demonstra:

- Capacidade de automação.
- Conhecimento em segurança.
- Conhecimento em Docker/OpenPanel.
- Integração de ferramentas corporativas.
- Entrega de valor para gestão.
- Redução de risco operacional.
- Criação de processo contínuo de segurança.

Frase sugerida para apresentação:

> Com este projeto, a equipe passa a ter visibilidade contínua dos riscos em containers, relatórios semanais para tomada de decisão e um processo claro de priorização de correções, reduzindo exposição a vulnerabilidades conhecidas e aumentando a maturidade de segurança da infraestrutura.

---

## 28. Entregáveis finais

| Entregável | Descrição |
|---|---|
| Código da solução | Scripts Bash/Python organizados |
| Dependency-Track | Ambiente funcional com projetos criados |
| Configuração de hosts | Arquivo `hosts.yml` |
| Relatório técnico | HTML/PDF gerado automaticamente |
| Relatório gerencial | HTML/PDF executivo |
| Histórico | Base com dados semanais |
| Dashboard | Grafana ou equivalente |
| Integração Zabbix | Métricas e triggers |
| Documentação | Instalação, operação e troubleshooting |
| Apresentação executiva | Material para demonstrar o projeto |

---

## 29. Próximos passos recomendados

1. Subir Dependency-Track em Docker Compose.
2. Instalar Trivy na máquina central.
3. Criar `hosts.yml` com 1 host piloto.
4. Criar script de inventário remoto.
5. Criar script de scan Trivy.
6. Gerar SBOM CycloneDX.
7. Enviar SBOM para Dependency-Track.
8. Gerar primeiro relatório técnico.
9. Criar relatório gerencial simplificado.
10. Apresentar resultado inicial com antes/depois.

---

## 30. Conclusão

O Container Security Monitor para Docker/OpenPanel é um projeto com alto valor técnico e gerencial. Ele resolve um problema real de visibilidade, risco e priorização em ambientes baseados em containers.

A solução proposta transforma scans isolados em um processo contínuo de governança de vulnerabilidades, com SBOM, Dependency-Track, MITRE ATT&CK, score de risco, histórico, dashboards e relatórios.

Se bem executado, o projeto pode se tornar uma entrega estratégica para a empresa, com impacto direto na maturidade de segurança, redução de risco e valorização profissional de quem o implementa.
