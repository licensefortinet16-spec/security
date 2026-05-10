# Spec Driven Development - Container Security Monitor

Data: 2026-05-09
Status: Draft inicial para MVP
Origem: `security/docs/prd-container-security-monitor.md`

## 1. Objetivo

Construir uma plataforma backend-first para monitorar riscos de seguranca em hosts Docker/OpenPanel, com inventario remoto, scan de vulnerabilidades, geracao de SBOM, envio ao Dependency-Track, score de risco, historico e relatorios tecnico/gerencial.

O MVP deve provar o fluxo ponta a ponta em um host piloto:

- Servidor central de trabalho: `192.168.1.22:/opt/security`
- Host alvo piloto: `192.168.1.30`
- Acesso operacional: SSH por chave como `root`
- Execucao inicial: manual, antes de agendamento via systemd
- Regra de execucao: scanner, Trivy, Dependency-Track client, score, parsing, relatorios e qualquer processamento rodam somente no servidor central `192.168.1.22`
- Regra para alvo: o host `192.168.1.30` nao deve receber instalacao do agente, Trivy, jobs, containers auxiliares ou processamento local da solucao

## 2. Principio mandatorio de seguranca: backend-only

Regra obrigatoria:

> Todo processamento de seguranca deve ocorrer exclusivamente no backend. Nenhum processamento sensivel, varredura, enriquecimento, calculo de risco, parsing de SBOM, chamada ao Dependency-Track, manipulacao de segredo, execucao SSH, comando Docker ou decisao de severidade pode ocorrer no frontend.

Implicacoes tecnicas:

- O frontend, quando existir, sera apenas uma camada autenticada de consulta e visualizacao.
- O frontend so podera consumir dados ja processados, normalizados e sanitizados por APIs backend.
- O frontend nao deve receber chaves SSH, API keys, `.env`, comandos shell, paths internos sensiveis, SBOM bruto completo por padrao ou dados que permitam pivot operacional.
- O backend sera responsavel por autenticacao, autorizacao, RBAC, auditoria, rate limit, validacao de input e logs.
- O backend sera o unico componente autorizado a acessar `/opt/security/config`, Dependency-Track, hosts via SSH, Docker remoto e arquivos de output.
- Relatorios publicados para frontend devem ser copias sanitizadas ou renderizacoes controladas geradas pelo backend.
- O host alvo deve ser tratado como fonte de dados operacional, nao como executor de processamento da plataforma.

Critério de aceite da regra:

- Qualquer PR que mova logica de scan, score, enriquecimento, upload, parsing, correlacao MITRE ou acesso a segredo para frontend deve ser rejeitado.
- Testes de arquitetura devem verificar que modulos frontend nao importam bibliotecas de scan, clients SSH, clients Docker, parsers de SBOM ou clients Dependency-Track.

## 3. Escopo do MVP

Incluido no MVP:

- Configuracao de hosts monitorados em YAML.
- Teste de conectividade SSH por host.
- Inventario remoto de containers, imagens, portas, volumes, redes, labels e usuario configurado.
- Identificacao de configuracoes inseguras em containers.
- Scan de imagens com Trivy.
- Geracao de SBOM CycloneDX por imagem unica.
- Upload de SBOM para Dependency-Track.
- Consulta basica de resultados no Dependency-Track.
- Calculo de score de risco por host, imagem e container.
- Relatorio tecnico em HTML e JSON.
- Relatorio gerencial simples em HTML.
- Historico por execucao.
- Logs estruturados.

Fora do MVP:

- Correcao automatica de vulnerabilidades.
- Bloqueio de containers.
- EDR/runtime protection.
- Kubernetes.
- Pentest automatizado.
- Frontend interativo completo.

## 4. Arquitetura proposta

Componentes backend:

- `scanner`: orquestra conexao SSH, inventario Docker, Trivy e SBOM.
- `collectors`: coleta inventario de containers e imagens.
- `checks`: avalia configuracoes inseguras.
- `sbom`: gera e valida CycloneDX.
- `dtrack`: envia SBOM e consulta resultados no Dependency-Track.
- `risk`: calcula score e SLA.
- `enrichment`: correlaciona achados com MITRE ATT&CK de forma aproximada.
- `reports`: gera HTML/PDF/JSON/CSV.
- `integrations`: publica metricas em Zabbix/Grafana.
- `scheduler`: systemd service/timer.

Modelo de execucao:

- O servidor central `192.168.1.22` executa todo o pipeline.
- O host alvo `192.168.1.30` e acessado por SSH apenas para coleta de inventario Docker e metadados necessarios.
- Trivy roda exclusivamente em `192.168.1.22`.
- Dependency-Track, score, MITRE, historico e relatorios rodam exclusivamente em `192.168.1.22`.
- O alvo nao deve executar Trivy, scripts persistentes, agentes, containers da solucao ou tarefas agendadas da plataforma.
- Para scan de imagens, o backend central deve preferir puxar as imagens por registry a partir do `192.168.1.22`.
- Imagens locais que existam somente no alvo exigem uma decisao operacional: publicar em registry privado ou permitir uma coleta controlada de artefato de imagem. Essa excecao deve ser configuravel, auditada e desabilitada por padrao.

Diretorio alvo:

```text
/opt/security/
  scanner/
  collectors/
  checks/
  sbom/
  dtrack/
  risk/
  enrichment/
  reports/
  integrations/
  config/
  output/
    inventory/
    trivy/
    sbom/
    reports/
    history/
    logs/
  systemd/
  docs/
  specs/
```

## 5. Requisitos funcionais

### RF01 - Cadastro de hosts

O backend deve carregar hosts de `config/hosts.yml`.

Campos minimos:

- `name`
- `ip`
- `ssh_user`
- `environment`
- `criticality`
- `openpanel`
- `internet_exposed`

Criterios de aceite:

- Suporta multiplos hosts.
- Falha em um host nao interrompe os demais.
- Host sem SSH funcional aparece no relatorio como falha de scan.
- O backend deve normalizar o contexto dos containers a partir de labels padronizados.
- Labels aceitos para contexto: `com.docker.compose.project`, `io.docker.compose.project`, `com.openpanel.context`, `openpanel.context`, `app.openpanel.context` e `context`.
- Se o container nao expuser label de contexto, o backend deve classificá-lo como `docker default`.
- Se o valor do label contiver referencia a OpenPanel, o contexto canonico deve ser `openpanel`.
- Contextos customizados devem manter o nome original normalizado em lowercase.

### RF02 - Inventario remoto Docker

O backend deve coletar via SSH:

- containers em execucao e parados;
- imagem, tag, id e digest quando disponivel;
- portas, volumes, networks, labels;
- usuario efetivo/configurado;
- status, healthcheck, created_at;
- flags relevantes de seguranca.

Criterios de aceite:

- Gera JSON bruto em `output/inventory`.
- Gera CSV consolidado para analise.
- Registra timestamp e host de origem.

### RF03 - Checks de configuracao insegura

O backend deve detectar:

- privileged container;
- `network_mode=host`;
- `pid_mode=host`;
- docker socket montado;
- diretorios sensiveis montados;
- execucao como root;
- ausencia de healthcheck;
- tag `latest`;
- capabilities perigosas;
- portas expostas;
- ausencia de limites de CPU/memoria.

Criterios de aceite:

- Cada achado possui severidade, evidencia e recomendacao.
- Achados entram no score de risco.

### RF04 - Scan Trivy

O backend deve executar Trivy no servidor central `192.168.1.22` para cada imagem unica por ciclo.

Criterios de aceite:

- Resultado JSON por imagem.
- Falhas de scan sao registradas sem interromper o ciclo.
- Nao duplica scan para mesma imagem/tag/digest no mesmo ciclo.
- Nenhum comando `trivy` e executado no host alvo.
- O alvo nao recebe instalacao de Trivy, cache de vulnerabilidades ou artefatos de scan.
- Quando a imagem nao puder ser obtida pelo servidor central, o resultado deve ser registrado como `image_unavailable_for_central_scan`, com recomendacao de publicar a imagem em registry acessivel ao scanner.

### RF05 - SBOM CycloneDX

O backend deve gerar SBOM CycloneDX por imagem unica.

Criterios de aceite:

- Arquivo JSON por imagem em `output/sbom`.
- Nome padronizado com host/imagem/data.
- Validacao basica de schema/estrutura antes do upload.

### RF06 - Dependency-Track

O backend deve enviar SBOMs para Dependency-Track usando `.env` protegido.

Criterios de aceite:

- Cria ou atualiza projeto.
- Armazena UUID do projeto.
- Registra sucesso/falha de upload.
- Nunca grava API key em log.

### RF07 - Score de risco

O backend deve calcular score limitado a 100.

Pesos iniciais:

- CVE critica: +30
- CVE alta: +15
- exploit conhecido: +25
- exposicao a internet: +20
- privileged: +20
- docker socket: +25
- root: +10
- latest: +5
- imagem antiga: +10
- sem fix disponivel: +5

Criterios de aceite:

- Pesos configuraveis em `config/severity_policy.yml`.
- Classificacao: baixo, medio, alto, critico.
- Score aparece no relatorio tecnico e gerencial.

### RF08 - Relatorios

O backend deve gerar:

- tecnico: HTML, JSON e CSV;
- gerencial: HTML;
- PDF no MVP se houver renderizador instalado.

Criterios de aceite:

- Relatorio tecnico contem evidencias suficientes para correcao.
- Relatorio gerencial evita excesso de CVEs e foca em risco, tendencia e prioridade.

### RF09 - Historico

O backend deve salvar snapshot por execucao.

Criterios de aceite:

- Permite comparar execucao atual com anterior.
- Mantem dados minimos para tendencia semanal.

## 6. Requisitos nao funcionais

- SSH somente com chave.
- Secrets apenas em `.env` protegido, fora do versionamento.
- Permissoes restritas em `/opt/security/config`.
- Logs sem secrets.
- Timeouts por host e por scan.
- Paralelismo controlado.
- Execucao idempotente.
- Codigo de saida compativel com monitoramento.
- Retencao configuravel para logs, SBOMs, historico e relatorios.

## 7. Modelo de dados minimo

Entidades:

- `ScanRun`: id, started_at, finished_at, status, duration, errors.
- `Host`: name, ip, environment, criticality, openpanel, internet_exposed.
- `Container`: host, id, name, image, status, ports, volumes, networks, user.
- `Image`: name, tag, digest, first_seen, last_seen.
- `Finding`: type, severity, evidence, recommendation, host, container, image.
- `Vulnerability`: cve, severity, package, installed_version, fixed_version, references.
- `Sbom`: path, image, generated_at, dtrack_project_uuid, upload_status.
- `RiskScore`: scope, score, classification, factors.

## 8. Fluxo de execucao

1. Carregar configuracoes.
2. Validar secrets e dependencias.
3. Testar SSH de cada host.
4. Coletar inventario Docker.
5. Deduplicar imagens.
6. Executar checks de configuracao.
7. Resolver origem das imagens para scan no servidor central.
8. Executar Trivy por imagem unica exclusivamente no servidor central.
9. Gerar SBOM CycloneDX no servidor central.
10. Enviar SBOM para Dependency-Track.
11. Consultar resultados.
12. Calcular score e SLA.
13. Correlacionar MITRE de forma aproximada.
14. Persistir historico.
15. Gerar relatorios.
16. Publicar metricas/alertas quando configurado.

## 9. Politica de falhas aceitaveis

Falhas aceitaveis sao aquelas que nao devem abortar todo o ciclo, desde que sejam registradas, aparecam no relatorio e produzam codigo de saida compativel com monitoramento.

Regras:

- Falha de SSH em um host: marcar host como `scan_failed`, registrar motivo e continuar demais hosts.
- Falha de inventario Docker em um host: marcar host como `inventory_failed`, registrar stdout/stderr sanitizado e continuar demais hosts.
- Imagem indisponivel para scan central: marcar imagem como `image_unavailable_for_central_scan`, nao tentar executar Trivy no alvo e seguir demais imagens.
- Falha Trivy em uma imagem: marcar imagem como `trivy_failed`, preservar erro sanitizado e seguir demais imagens.
- Falha na geracao de SBOM: marcar imagem como `sbom_failed`, nao tentar upload e seguir demais imagens.
- Dependency-Track indisponivel: salvar SBOM em fila local de retry, marcar upload como `pending_retry` e continuar relatorios com dados locais.
- Falha de relatorio PDF: manter HTML/JSON/CSV como saida valida e marcar PDF como `pdf_failed`.
- Falha de Zabbix/Grafana: registrar `metrics_publish_failed`, mas nao invalidar o scan.

Severidade operacional:

- `success`: todos os hosts e imagens processados.
- `partial_success`: um ou mais itens falharam, mas houve relatorio e historico.
- `failed`: nenhuma coleta valida foi concluida ou erro estrutural impediu relatorio.

Codigos de saida recomendados:

- `0`: success.
- `1`: partial_success com falhas operacionais tratadas.
- `2`: failed por erro estrutural, configuracao invalida ou ausencia total de dados.

## 10. Testes de aceite do MVP

- `ssh root@192.168.1.30 "docker ps"` funciona a partir do servidor central.
- Inventario JSON contem todos os containers retornados por Docker.
- Imagens repetidas sao escaneadas uma unica vez por ciclo.
- Pelo menos um SBOM CycloneDX e gerado com sucesso.
- Upload para Dependency-Track retorna sucesso ou erro tratado.
- Relatorio tecnico e gerado mesmo quando um host falha.
- Relatorio gerencial apresenta risco geral e top riscos.
- Nenhum log contem API key, chave privada ou segredo.
- Nenhum modulo frontend executa processamento sensivel.
- `trivy` e executado somente em `192.168.1.22`.
- O host alvo nao recebe agente, Trivy, containers auxiliares ou tarefas persistentes da solucao.
- Imagem nao disponivel ao scanner central gera falha tratada, nao processamento no alvo.

## 11. Roadmap recomendado

Fase 0 - Preparacao:

- Instalar dependencias no servidor central.
- Criar estrutura `/opt/security`.
- Copiar PRD e spec.
- Criar `hosts.yml` para `192.168.1.30`.
- Validar SSH central -> alvo.
- Instalar Trivy somente em `192.168.1.22`.
- Definir como o scanner central acessara as imagens: registry, credenciais de registry ou excecao controlada.

Fase 1 - MVP tecnico:

- Implementar inventario remoto.
- Implementar checks de configuracao.
- Integrar Trivy e SBOM.
- Criar relatorio tecnico simples.

Fase 2 - Governanca:

- Dependency-Track.
- Score de risco.
- Historico semanal.
- Relatorio gerencial.

Fase 3 - Operacao:

- systemd timer.
- Zabbix/Grafana.
- Alertas.
- Hardening e backup.

## 12. Decisoes iniciais

- O processamento sera backend-only por desenho.
- O alvo piloto sera `192.168.1.30`.
- O servidor central sera `192.168.1.22`.
- Trivy roda somente no servidor central `192.168.1.22`.
- O servidor que hospeda clientes nao deve executar processamento da solucao.
- A primeira implementacao deve favorecer scripts backend simples e auditaveis antes de qualquer portal web.
- Dependency-Track e Trivy sao dependencias centrais do fluxo.
- MITRE ATT&CK sera tratado como correlacao aproximada, nao como atribuicao absoluta.
