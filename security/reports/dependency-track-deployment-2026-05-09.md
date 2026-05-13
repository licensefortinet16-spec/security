# Dependency-Track Deployment - 2026-05-09

## Status

Servidor central:

- Host: `200.160.19.14`
- Diretorio: `/opt/security/security/dtrack`
- Docker: instalado
- Docker Compose: instalado
- Dependency-Track API: saudavel
- Dependency-Track Frontend: em execucao
- PostgreSQL: saudavel

Versao observada:

- Dependency-Track: `4.14.2`
- Alpine framework: `3.7.0`

## Exposicao de rede

As portas foram publicadas apenas em loopback no servidor central:

| Servico | Bind |
|---|---|
| Frontend | `127.0.0.1:8080` |
| API | `127.0.0.1:8081` |

Isso evita exposicao direta na rede. Para acessar a partir da estacao de trabalho:

```bash
ssh -L 8080:127.0.0.1:8080 -L 8081:127.0.0.1:8081 root@200.160.19.14
```

Depois abrir:

```text
http://127.0.0.1:8080
```

## Credenciais iniciais

O Dependency-Track cria o usuario inicial:

- Usuario: `admin`
- Senha inicial: `admin`

Na primeira autenticacao, a senha deve ser alterada.

## API key

A partir da interface administrativa:

1. Entrar no frontend via tunel SSH.
2. Alterar a senha inicial.
3. Criar ou selecionar um time com permissoes de BOM upload e portfolio.
4. Gerar uma API key.
5. Configurar no servidor central:

```bash
cd /opt/security/security
./dtrack/configure_api_key.sh 'cole-a-api-key-aqui'
```

O arquivo gerado sera:

```text
/opt/security/security/config/dependency-track.env
```

com permissao `600`.

## Observacao de capacidade

O servidor central possui aproximadamente 1.9 GiB de RAM. A documentacao oficial do Dependency-Track informa minimo de 2 GiB para o API Server e recomenda 8 GiB. O servico subiu e ficou saudavel, mas esta no limite de memoria para uso continuo.

Recomendacao:

- manter monitoramento de memoria e swap;
- preferir 4 GiB como minimo operacional para piloto confortavel;
- usar 8 GiB se o ambiente crescer em quantidade de SBOMs/projetos.

## Validacao

Comandos usados:

```bash
cd /opt/security/security/dtrack
docker compose ps
curl -fsS http://127.0.0.1:8081/api/version
docker stats --no-stream dtrack-apiserver dtrack-frontend dtrack-postgres
```

Resultado operacional:

- API respondeu `/api/version`.
- Containers ativos.
- Portas restritas a `127.0.0.1`.
- Scan principal continua funcionando quando Dependency-Track ainda nao possui API key, retornando `skipped_not_configured`.
