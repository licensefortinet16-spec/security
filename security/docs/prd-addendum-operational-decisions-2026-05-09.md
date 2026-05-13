# Addendum ao PRD - Decisoes Operacionais

Data: 2026-05-09

Este addendum complementa o PRD original com decisoes de execucao para o ambiente piloto.

## 1. Execucao centralizada

O scanner deve rodar no servidor central:

- Servidor executor: `200.160.19.14`
- Diretorio de trabalho: `/opt/security/security`
- Host alvo piloto: `200.160.19.2`

Todo processamento deve ocorrer em `200.160.19.14`, incluindo:

- orquestracao do scan;
- execucao do Trivy;
- geracao de SBOM;
- upload para Dependency-Track;
- consulta ao Dependency-Track;
- score de risco;
- correlacao MITRE;
- historico;
- relatorios;
- metricas e alertas.

## 2. Restricao no servidor de clientes

O servidor `200.160.19.2`, por hospedar clientes, nao deve executar componentes da solucao.

Nao permitido no alvo:

- instalar Trivy para esta solucao;
- instalar agente persistente;
- executar containers auxiliares da plataforma;
- manter cache de vulnerabilidades;
- gerar SBOM localmente;
- processar score, relatorio ou enriquecimento;
- executar tarefas agendadas da plataforma.

Permitido no alvo:

- responder SSH autorizado;
- executar consultas minimas e auditaveis de inventario Docker;
- expor metadados necessarios para que o servidor central faca o processamento.

## 3. Implicacao para scan de imagens

Como o Trivy roda somente em `200.160.19.14`, o scanner central precisa conseguir acessar as imagens por uma destas formas:

- registry publico;
- registry privado com credenciais configuradas no servidor central;
- imagem publicada previamente em registry interno;
- excecao operacional controlada para transferencia de artefato de imagem, se aprovada.

Regra padrao:

- Se uma imagem existir somente localmente no `200.160.19.2` e nao puder ser obtida pelo `200.160.19.14`, o scan dessa imagem deve falhar de forma tratada com status `image_unavailable_for_central_scan`.
- A solucao nao deve contornar essa falha executando Trivy no alvo.

## 4. Politica de falhas aceitaveis

Falhas tratadas nao devem abortar todo o ciclo quando ainda for possivel gerar relatorio parcial.

Classificacao:

- `success`: todos os hosts e imagens processados.
- `partial_success`: uma ou mais falhas tratadas ocorreram, mas houve coleta, historico e relatorio.
- `failed`: erro estrutural impediu coleta valida ou geracao de relatorio.

Regras:

- Falha em um host nao interrompe outros hosts.
- Falha em uma imagem nao interrompe outras imagens.
- Falha de Dependency-Track deixa SBOM pendente para retry.
- Falha de PDF nao invalida HTML/JSON/CSV.
- Falha de Zabbix/Grafana nao invalida o scan.
- Toda falha deve aparecer no relatorio tecnico e nos logs sanitizados.

Codigos de saida recomendados:

- `0`: `success`
- `1`: `partial_success`
- `2`: `failed`

## 5. Requisito backend-only

A regra backend-only permanece obrigatoria:

- frontend apenas consulta dados processados;
- frontend nao executa scan;
- frontend nao acessa SSH, Docker, Trivy, SBOM bruto sensivel ou secrets;
- frontend nao calcula score nem severidade;
- qualquer logica sensivel fica restrita ao backend no servidor central.

## 6. Agenda configuravel de scans

O painel autenticado expoe `/settings` para configurar a agenda do ciclo completo de scan. A configuracao gravada em `/opt/security/security/config/scan_schedule.json` atualiza o timer `container-security-scan.timer` via systemd.

A agenda atual do piloto e diaria as 22:00 no fuso local do servidor central:

```text
OnCalendar=*-*-* 22:00:00
```

O botao de scan manual permanece disponivel na mesma tela para execucao pontual sem alterar a agenda.

## 7. Scan de codigo

A visao `/reports/code` representa achados de codigo-fonte e secrets. O fluxo copia os diretorios de clientes para o servidor central e executa Semgrep e verificacoes PHP leves. O Trivy fica restrito a `secret,misconfig` neste fluxo para evitar que CVEs de lockfiles e dependencias sejam confundidas com vulnerabilidades de codigo.
