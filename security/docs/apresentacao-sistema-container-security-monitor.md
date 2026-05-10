# Apresentacao do Sistema - Container Security Monitor

Data de referencia: 2026-05-10  
Ambiente piloto: `192.168.1.22:/opt/security`  
Host monitorado: `192.168.1.30`

## 1. Resumo executivo

O Container Security Monitor e uma plataforma centralizada para visibilidade de risco em ambientes Docker e OpenPanel. A solucao coleta inventario remoto, sincroniza imagens de forma controlada, executa Trivy somente no servidor central, gera SBOM CycloneDX, envia os SBOMs ao Dependency-Track, calcula score de risco, publica metricas e entrega relatorios tecnico e gerencial.

O ponto principal de seguranca da arquitetura e que todo processamento ocorre no backend, no servidor `192.168.1.22`. O host que hospeda clientes nao recebe agente, Trivy, container auxiliar, job agendado ou processamento local da solucao.

## 2. Problema resolvido

Ambientes com muitos containers tendem a perder visibilidade sobre:

- imagens antigas;
- tags mutaveis como `latest`;
- containers rodando como root;
- portas publicadas;
- falta de limites de CPU e memoria;
- falta de healthcheck;
- vulnerabilidades em pacotes e dependencias;
- ausencia de inventario e historico por contexto.

O sistema transforma essa visibilidade em um processo repetivel, mensuravel e apresentavel para operacao, SOC e gestao.

## 3. Principios de seguranca

- Todo processamento sensivel ocorre no backend.
- O frontend e os relatorios publicados exibem dados ja processados e sanitizados.
- O host alvo e tratado como fonte de dados, nao como executor da plataforma.
- Chaves, arquivos `.env`, SSH, chamadas Docker, Trivy, parsing de SBOM e correlacao com Dependency-Track ficam restritos ao servidor central.
- Regras de alerta nao bloqueiam containers ou deploys; elas sinalizam violacoes para acompanhamento operacional.

## 4. Arquitetura atual

```text
Usuario / SOC
   |
   | HTTP
   v
Status UI / Relatorios / Grafana
   |
   v
Servidor central 192.168.1.22
   |-- scanner e orquestracao
   |-- inventario Docker remoto via SSH
   |-- docker save controlado para imagens locais
   |-- Trivy local
   |-- SBOM CycloneDX
   |-- Dependency-Track
   |-- score de risco
   |-- alertas nao bloqueantes
   |-- Prometheus / Grafana
   |-- relatorios HTML e PDF
   |
   | SSH somente para coleta
   v
Host alvo 192.168.1.30
```

## 5. Componentes

| Componente | Funcao |
| --- | --- |
| `scanner` | Orquestra a execucao ponta a ponta. |
| `collectors` | Coleta inventario remoto de containers, imagens, labels, portas, volumes e configuracoes. |
| `trivy_central_scan` | Executa Trivy somente no servidor central. |
| `sync_images_from_targets` | Usa `docker save` via SSH para disponibilizar imagens locais ao scanner central, sem instalar nada no alvo. |
| `dtrack` | Faz upload de SBOMs e consulta correlacao no Dependency-Track. |
| `reports` | Gera relatorio gerencial, tecnico, paginas por container e PDF. |
| `integrations` | Exporta alertas e metricas para Prometheus, Grafana e Zabbix payload. |
| `server` | Publica status, metricas e relatorios via HTTP. |
| `observability` | Sobe Prometheus e Grafana locais. |

## 6. Fluxo operacional

1. O backend le `config/hosts.yml`.
2. O servidor central testa acesso SSH ao host monitorado.
3. O inventario Docker e coletado remotamente.
4. Imagens locais podem ser sincronizadas para o servidor central por `docker save`.
5. Trivy roda localmente no `192.168.1.22`.
6. SBOM CycloneDX e gerado por imagem.
7. SBOMs sao enviados ao Dependency-Track.
8. Dependency-Track correlaciona componentes e vulnerabilidades.
9. O backend calcula score por container e contexto.
10. Alertas nao bloqueantes sao avaliados.
11. Relatorios HTML/PDF e metricas sao publicados.
12. Grafana exibe dashboards por contexto e regras ativas.

## 7. Estado atual do piloto

Dados da ultima execucao validada:

| Indicador | Valor |
| --- | ---: |
| Hosts analisados | 1/1 |
| Containers inventariados | 10 |
| Imagens analisadas | 9 |
| Achados de configuracao | 50 |
| Vulnerabilidades Trivy | 1686 |
| Criticas | 73 |
| Altas | 504 |
| Medias | 644 |
| Baixas | 409 |
| Unknown | 56 |
| SBOMs enviados ao Dependency-Track | 9 |
| Projetos encontrados no Dependency-Track | 9 |
| Componentes no Dependency-Track | 6434 |
| Vulnerabilidades correlacionadas no Dependency-Track | 1487 |
| Componentes vulneraveis no Dependency-Track | 398 |
| Alertas ativos | 4 |

Contexto detectado:

| Contexto | Containers | Score maximo | Score medio | Achados |
| --- | ---: | ---: | ---: | ---: |
| `automated-zap` | 10 | 100 | 94.2 | 2052 |

## 8. Regras de alerta ativas

As regras sao apenas informativas. Elas nao bloqueiam containers, deploys ou execucoes.

| Regra | Condicao | Severidade | Estado atual |
| --- | --- | --- | --- |
| `critical_vulnerabilities` | criticas > 0 | critical | ativo |
| `high_vulnerabilities` | altas >= 10 | warning | ativo |
| `risk_score_high` | score maximo >= 80 | warning | ativo |
| `dtrack_vulnerable_components` | componentes vulneraveis > 0 | warning | ativo |
| `dtrack_correlation_gap` | falha de correlacao DT | warning | ok |
| `scan_failure` | falha de scan | critical | ok |

## 9. Relatorios disponiveis

| Recurso | URL |
| --- | --- |
| Status UI | `http://192.168.1.22:8090` |
| Relatorio gerencial HTML | `http://192.168.1.22:8090/reports/executive` |
| Relatorio gerencial PDF | `http://192.168.1.22:8090/reports/executive.pdf` |
| Relatorio tecnico geral | `http://192.168.1.22:8090/reports/technical` |
| Grafana | `http://192.168.1.22:3000` |
| Prometheus | `http://192.168.1.22:9090` |
| Dependency-Track | `http://192.168.1.22:8080` |
| Dependency-Track API | `http://192.168.1.22:8081` |

O relatorio tecnico possui menu lateral com grupos expansives:

- Containers;
- Secoes do relatorio;
- Vulnerabilidades por container;
- Score por container;
- Vulnerabilidades prioritarias;
- Achados de configuracao;
- Dependency-Track.

Cada container pode ser aberto individualmente para visualizar apenas os dados daquele container/imagem.

## 10. Roteiro sugerido para apresentacao

### Abertura

Mensagem central:

> O sistema entrega visibilidade continua de risco em containers sem instalar nada no host que hospeda clientes. Todo o processamento fica concentrado no backend, com relatorios e alertas prontos para SOC e gestao.

### Demonstracao 1 - Status UI

Abrir:

```text
http://192.168.1.22:8090
```

Mostrar:

- status da ultima execucao;
- total de containers;
- total de vulnerabilidades;
- top riscos;
- links para relatorios.

### Demonstracao 2 - Relatorio gerencial

Abrir:

```text
http://192.168.1.22:8090/reports/executive
```

Mostrar:

- risco geral;
- KPIs executivos;
- vulnerabilidades por severidade;
- contextos prioritarios;
- tendencia historica;
- plano de acao recomendado.

Em seguida abrir:

```text
http://192.168.1.22:8090/reports/executive.pdf
```

Ponto de fala:

> O PDF e gerado no backend e carrega os graficos principais, permitindo envio para gestao sem depender de acesso ao sistema.

### Demonstracao 3 - Relatorio tecnico

Abrir:

```text
http://192.168.1.22:8090/reports/technical
```

Mostrar:

- menu lateral expansivel;
- lista de containers;
- vulnerabilidades por container;
- score por container;
- plano de acao com SLA;
- achados de configuracao;
- correlacao Dependency-Track.

Abrir um container, por exemplo:

```text
http://192.168.1.22:8090/reports/technical/containers/radius-automated-zap-mailpit-axllent-mailpit-latest
```

Ponto de fala:

> A equipe tecnica consegue sair do panorama geral para o detalhe de um container especifico, com CVEs, pacote afetado, versao instalada, versao corrigida e recomendacao.

### Demonstracao 4 - Grafana

Abrir:

```text
http://192.168.1.22:3000
```

Mostrar:

- alertas ativos;
- regras violadas;
- visao por contexto;
- risco por container;
- metricas para SOC.

### Demonstracao 5 - Dependency-Track

Abrir:

```text
http://192.168.1.22:8080
```

Mostrar:

- projetos criados por imagem;
- SBOMs importados;
- correlacao de vulnerabilidades;
- visao de componentes vulneraveis.

Ponto de fala:

> Trivy e a fonte local de descoberta. Dependency-Track e a camada de governanca, inventario de componentes, correlacao e acompanhamento continuo.

## 11. Diferenciais tecnicos

- Arquitetura backend-only.
- Sem agente no host alvo.
- Trivy roda somente no servidor central.
- Suporte a Docker/OpenPanel por contexto.
- Relatorio gerencial com PDF.
- Relatorio tecnico com drill-down por container.
- Dependency-Track integrado e correlacionando.
- Alertas nao bloqueantes para SOC.
- Grafana e Prometheus locais, sem dependencia de internet.
- Preparado para execucao manual ou agendada via systemd.
- Historico de execucoes para tendencia.

## 12. Pontos de atencao

- O piloto atualmente mostra alto volume de vulnerabilidades criticas e altas.
- O uso de tags `latest` deve ser reduzido.
- Containers sem limite de CPU/memoria devem receber limites operacionais.
- Containers rodando como root devem ser revisados.
- Portas publicadas devem ser protegidas por firewall ou reverse proxy.
- A estrategia para imagens privadas deve ser padronizada: registry privado ou sincronizacao controlada via `docker save`.

## 13. Proximos passos recomendados

1. Definir baseline aceitavel por contexto.
2. Ajustar politicas de alerta por criticidade do servico.
3. Separar responsabilidades por equipe/contexto.
4. Criar rotina semanal de revisao dos top riscos.
5. Integrar notificacoes para o SOC.
6. Adicionar autenticacao/controle de acesso ao status server antes de producao.
7. Padronizar labels de contexto nos `docker-compose.yml`.
8. Criar processo de excecao documentada para vulnerabilidades sem correcao.

## 14. Mensagem final para gestao

O sistema reduz a falta de visibilidade em ambientes Docker/OpenPanel e cria uma rotina centralizada para identificar, priorizar e acompanhar riscos. A solucao evita instalar componentes no host de clientes, concentra o processamento no backend e entrega informacao em tres niveis: executivo, tecnico e operacional/SOC.

