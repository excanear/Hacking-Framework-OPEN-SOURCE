<div align="center">

# 🛡️ Security Research Platform

**Plataforma modular e robusta de pesquisa e automação em cibersegurança**

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0%2B-red)](https://sqlalchemy.org)
[![Celery](https://img.shields.io/badge/Celery-5.4%2B-37814A?logo=celery)](https://docs.celeryq.dev)
[![Licença](https://img.shields.io/badge/Licença-MIT-yellow)](LICENSE)

> ⚠️ **Somente para testes de segurança autorizados.**  
> Utilize esta ferramenta apenas em sistemas que você possui ou para os quais possui **autorização explícita e por escrito**.  
> A varredura não autorizada pode violar leis de crimes cibernéticos na sua jurisdição.

</div>

---

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Funcionalidades](#-funcionalidades)
- [Arquitetura](#-arquitetura)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Início Rápido — Sem Docker](#-início-rápido--sem-docker)
- [Início Rápido — Docker Compose](#-início-rápido--docker-compose)
- [Referência de Configuração](#-referência-de-configuração)
- [API REST](#-api-rest)
- [CLI — Linha de Comando](#-cli--linha-de-comando)
- [Módulos de Segurança](#-módulos-de-segurança)
- [Motor de Inteligência](#-motor-de-inteligência)
- [Relatórios](#-relatórios)
- [Desenvolvimento](#-desenvolvimento)
- [Segurança em Produção](#-segurança-em-produção)
- [Solução de Problemas](#-solução-de-problemas)

---

## 🔍 Visão Geral

A **Security Research Platform** é um framework completo de automação de cibersegurança, pronto para uso em ambientes de produção. Ela oferece:

- Uma **API REST + WebSocket** (FastAPI) para controle programático e streaming de scans em tempo real
- Um **sistema de módulos por plugins** para facilitar a adição de novas capacidades de descoberta e análise
- Um **motor de inteligência** que correlaciona impressões digitais de serviços com dados de CVE e gera pontuações de risco compostas
- **Execução distribuída de tarefas** via Celery, para que varreduras pesadas nunca bloqueiem o servidor da API
- **Relatórios estruturados em HTML e JSON** com pontuação de risco, recomendações e todos os resultados brutos
- Um **painel web** para uma visão rápida da infraestrutura
- Uma **CLI** (`security`) para fluxos de trabalho diretos no terminal

Alvos suportados: domínios, IPs, redes CIDR, URLs e ativos em nuvem.

---

## ✨ Funcionalidades

### Plataforma Principal

| Funcionalidade | Descrição |
|---|---|
| Autenticação JWT | Token bearer com validade configurável |
| Controle de Acesso | Flag de superusuário para operações privilegiadas |
| Arquitetura Assíncrona | I/O não bloqueante em toda a stack (FastAPI + SQLAlchemy 2 async) |
| Workers Distribuídos | Celery com 3 filas: `scans`, `analysis`, `default` |
| Modo Dev | Funciona com SQLite + Celery em memória — sem dependências externas |
| Docker Pronto | Um único `docker compose up --build` para a stack completa de produção |

### Módulos de Segurança (7 módulos integrados)

| Módulo | Categoria | O que faz |
|---|---|---|
| `dns_enumeration` | Descoberta | Enumeração completa de registros DNS (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| `subdomain_discovery` | Descoberta | Descoberta passiva de subdomínios + transparência de certificados |
| `port_scanner` | Rede | Escaneamento TCP assíncrono nas portas mais comuns e personalizadas |
| `service_fingerprint` | Rede | Banner grabbing e identificação de serviço/versão |
| `dns_osint` | OSINT | SPF, DMARC, DKIM, CAA, DNSSEC e postura de segurança de e-mail |
| `web_analyzer` | Web | Cabeçalhos HTTP de segurança, nota TLS, flags de cookies, política CORS |
| `cloud_discovery` | Nuvem | Detecção de ativos em nuvem via padrões de delegação CNAME |

### Motor de Inteligência

| Componente | Descrição |
|---|---|
| Correlação de CVEs | Cruza serviços identificados com dataset de CVEs embutido + API NIST NVD |
| Pontuação de Risco | Nota composta de 0 a 10 com sub-notas para vulnerabilidades, exposição e configuração |
| Níveis de Risco | `mínimo` / `baixo` / `médio` / `alto` / `crítico` com recomendações acionáveis |

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Camada Cliente                              │
│             CLI (Typer) │ API REST │ Painel Web                     │
└────────────────┬──────────────────────────────────────┬────────────┘
                 │                                      │
┌────────────────▼──────────────────────────────────────▼────────────┐
│                      Aplicação FastAPI                              │
│  /api/v1/targets  │  /api/v1/scan  │  /api/v1/reports  │  /health  │
│  TrustedHostMiddleware + CORSMiddleware + JWT Bearer Auth           │
└────────────────┬──────────────────────────────────────┬────────────┘
                 │                                      │
     ┌───────────▼───────────┐              ┌───────────▼───────────┐
     │    Motor de Segurança │              │   Workers Celery       │
     │  PluginLoader         │◄────────────►│  scan_worker           │
     │  WorkflowEngine       │              │  analysis_worker       │
     │  Scheduler            │              └───────────┬───────────┘
     └───────────┬───────────┘                          │
                 │                          ┌───────────▼───────────┐
     ┌───────────▼───────────┐              │  Message Broker        │
     │   Sistema de Módulos  │              │  Redis (produção)      │
     │  dns_enumeration      │              │  memory:// (dev)       │
     │  subdomain_discovery  │              └───────────────────────┘
     │  port_scanner         │
     │  service_fingerprint  │
     │  dns_osint            │
     │  web_analyzer         │
     │  cloud_discovery      │
     └───────────┬───────────┘
                 │
     ┌───────────▼───────────┐
     │  Motor de Inteligência│
     │  Correlação de CVEs   │
     │  Fingerprint de Svc.  │
     │  Pontuação de Risco   │
     └───────────┬───────────┘
                 │
     ┌───────────▼───────────┐
     │    Camada de Dados    │
     │  SQLAlchemy 2 Async   │
     │  PostgreSQL (prod)    │
     │  SQLite (dev)         │
     └───────────────────────┘
```

---

## 📁 Estrutura do Projeto

```
security_platform/
│
├── api/                          # Camada REST + WebSocket (FastAPI)
│   ├── auth.py                   # Geração e verificação de JWT, hashing bcrypt
│   ├── server.py                 # Fábrica da aplicação, lifespan, middlewares
│   ├── routes_targets.py         # CRUD de alvos
│   ├── routes_scan.py            # Orquestração de scans + stream WebSocket ao vivo
│   └── routes_reports.py         # Requisição, geração e download de relatórios
│
├── cli/                          # Interface de linha de comando (Typer)
│   ├── cli.py                    # App raiz (serve / worker / flower)
│   └── commands/
│       ├── scan_commands.py      # scan run / discover / analyze / modules
│       ├── target_commands.py    # targets add / list / show / delete
│       └── report_commands.py    # report generate / list
│
├── config/
│   └── settings.py               # Pydantic-Settings: DB, Redis, Segurança, Worker
│
├── core/
│   ├── engine.py                 # Orquestrador central SecurityEngine
│   ├── plugin_loader.py          # Auto-descoberta de subclasses de SecurityModule
│   ├── workflow_engine.py        # Pipeline assíncrono com streaming de eventos
│   └── scheduler.py              # Abstração de despacho de tarefas Celery
│
├── database/
│   ├── database.py               # Fábrica de engine assíncrona (PostgreSQL/SQLite)
│   └── models.py                 # ORM: User, Target, Asset, Service, Vulnerability,
│                                 #       ScanResult, Report
│
├── modules/                      # Plugins de módulos de segurança
│   ├── base_module.py            # SecurityModule abstrato + ModuleResult
│   ├── discovery/
│   │   ├── dns_enum.py           # Enumeração de registros DNS
│   │   └── subdomain_discovery.py# Descoberta passiva de subdomínios
│   ├── network/
│   │   ├── port_scanner.py       # Scanner TCP assíncrono
│   │   └── service_fingerprint.py# Banner grab + identificação de produto/versão
│   ├── osint/
│   │   └── dns_osint.py          # SPF, DMARC, DKIM, CAA, DNSSEC
│   ├── web/
│   │   └── web_analyzer.py       # Cabeçalhos HTTP, TLS, cookies, CORS
│   └── cloud/
│       └── cloud_discovery.py    # Detecção de delegação de nuvem via CNAME
│
├── intelligence/
│   ├── cve_intelligence.py       # Busca CVE (API NVD + dataset embutido)
│   ├── fingerprint_engine.py     # Motor de correspondência serviço → produto
│   └── risk_engine.py            # Pontuação de risco composta 0–10
│
├── workers/
│   ├── worker_manager.py         # Fábrica Celery (3 filas, modo eager dev)
│   ├── scan_worker.py            # Tasks: run_full_scan_task, run_module_task
│   └── analysis_worker.py        # Tasks: run_analysis_task (CVE + risco)
│
├── reports/
│   ├── report_generator.py       # Orquestra dados, risco, exportação e persistência
│   └── exporters.py              # JSONExporter + HTMLExporter (Jinja2)
│
├── dashboard/
│   ├── backend/dashboard_api.py  # Endpoints de agregação para o frontend
│   └── frontend/index.html       # Painel web single-page
│
├── docker/
│   ├── Dockerfile                # Imagem Python multi-stage
│   └── docker-compose.yml        # Stack completa de produção (6 serviços)
│
├── .env.example                  # Template — copie para .env antes de executar
├── .gitignore
├── main.py                       # Entry point do Uvicorn
├── pyproject.toml
└── requirements.txt
```

---

## 🚀 Início Rápido — Sem Docker

Ideal para desenvolvimento local. Roda com **SQLite** e **Celery em memória** — sem PostgreSQL ou Redis.

### Pré-requisitos

- Python 3.12 ou superior
- Git

### 1. Clonar e instalar

```bash
git clone https://github.com/seu-usuario/security-platform.git
cd security-platform/security_platform

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Criar o arquivo de ambiente para desenvolvimento

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Abra o `.env` e configure no mínimo:

```env
# ── Usar SQLite no lugar do PostgreSQL ────────────────────────────────────────
DATABASE_URL=sqlite+aiosqlite:///./security_platform_dev.db

# ── Rodar tasks Celery em processo (sem Redis) ────────────────────────────────
CELERY_TASK_ALWAYS_EAGER=true

# ── Gere sua própria chave secreta ────────────────────────────────────────────
SECURITY_SECRET_KEY=chave-secreta-dev-troque-em-producao

ENVIRONMENT=development
DEBUG=true
```

### 3. Iniciar o servidor da API

```bash
# Windows
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000

# Linux / macOS
uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Saída esperada:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

### 4. Verificar se está funcionando

```bash
curl http://127.0.0.1:8000/health
# → {"status": "ok", "version": "1.0.0"}
```

Documentação interativa da API: **http://127.0.0.1:8000/docs**

### 5. Registrar conta e executar o primeiro scan

```bash
# Registrar usuário
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@exemplo.com","password":"Admin@1234!"}'

# Login — copie o access_token da resposta
curl -X POST http://127.0.0.1:8000/api/v1/auth/token \
  -d "username=admin&password=Admin@1234!"

# Criar alvo (use um domínio que você tem autorização para testar)
curl -X POST http://127.0.0.1:8000/api/v1/targets \
  -H "Authorization: Bearer <seu-token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Minha Empresa","value":"seudominio.com.br","target_type":"domain"}'

# Iniciar scan completo
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Authorization: Bearer <seu-token>" \
  -H "Content-Type: application/json" \
  -d '{"target_id":"<id-do-alvo-criado-acima>"}'

# Verificar status do scan
curl http://127.0.0.1:8000/api/v1/scan/<id-do-scan> \
  -H "Authorization: Bearer <seu-token>"
```

---

## 🐳 Início Rápido — Docker Compose

Stack completa de produção com PostgreSQL, Redis, workers Celery e monitoramento Flower.

### Pré-requisitos

- Docker 24+
- Docker Compose 2.20+

### 1. Clonar e configurar

```bash
git clone https://github.com/seu-usuario/security-platform.git
cd security-platform/security_platform

cp .env.example .env
# Edite o .env — defina senhas fortes para DB_PASSWORD e SECURITY_SECRET_KEY
```

### 2. Subir os serviços

```bash
cd docker
docker compose up --build
```

### 3. Endpoints disponíveis

| Serviço | URL | Descrição |
|---|---|---|
| API + Docs | http://localhost:8000/docs | Swagger UI da API FastAPI |
| Painel Web | http://localhost:8000 | Dashboard de infraestrutura |
| Health Check | http://localhost:8000/health | Probe para load balancer |
| Flower | http://localhost:5555 | Monitoramento dos workers Celery |

### 4. Parar e limpar

```bash
docker compose down        # para os serviços, mantém os volumes
docker compose down -v     # para e apaga todos os dados
```

---

## ⚙️ Referência de Configuração

Toda a configuração é gerenciada via variáveis de ambiente ou arquivo `.env`. Copie `.env.example` para `.env` e ajuste conforme necessário.

### Aplicação

| Variável | Padrão | Descrição |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` ou `production` |
| `DEBUG` | `false` | Ativa logs de debug e o endpoint `/docs` |
| `LOG_LEVEL` | `INFO` | Nível de log do Python |

### Banco de Dados

| Variável | Padrão | Descrição |
|---|---|---|
| `DATABASE_URL` | *(não definido)* | DSN completo — sobrescreve todos os campos `DB_*`. Use `sqlite+aiosqlite:///./dev.db` para dev sem Docker |
| `DB_HOST` | `localhost` | Host do PostgreSQL |
| `DB_PORT` | `5432` | Porta do PostgreSQL |
| `DB_NAME` | `security_platform` | Nome do banco de dados |
| `DB_USER` | `secplatform` | Usuário do banco |
| `DB_PASSWORD` | `changeme_in_production` | **Troque obrigatoriamente em produção** |
| `DB_POOL_SIZE` | `10` | Tamanho do pool de conexões SQLAlchemy |

### Redis

| Variável | Padrão | Descrição |
|---|---|---|
| `REDIS_HOST` | `localhost` | Host do Redis |
| `REDIS_PORT` | `6379` | Porta do Redis |
| `REDIS_PASSWORD` | *(vazio)* | Senha de autenticação do Redis |

### Segurança

| Variável | Padrão | Descrição |
|---|---|---|
| `SECURITY_SECRET_KEY` | *(aleatório)* | Chave de assinatura JWT — **gere um valor aleatório forte** |
| `SECURITY_ALGORITHM` | `HS256` | Algoritmo JWT |
| `SECURITY_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Validade do token em minutos |
| `SECURITY_ALLOWED_HOSTS` | `["*"]` | Lista JSON de valores permitidos no header `Host` |
| `SECURITY_CORS_ORIGINS` | `["http://localhost:8000"]` | Lista JSON de origens CORS permitidas |

### Workers

| Variável | Padrão | Descrição |
|---|---|---|
| `CELERY_TASK_ALWAYS_EAGER` | `false` | Executa tasks Celery em processo (modo dev, sem Redis) |
| `WORKER_CONCURRENCY` | `4` | Concorrência dos workers Celery |
| `SCAN_TIMEOUT_SECONDS` | `300` | Tempo máximo em segundos para uma task de scan |

### Opcionais

| Variável | Padrão | Descrição |
|---|---|---|
| `ES_ENABLED` | `false` | Ativa indexação de resultados no Elasticsearch |
| `ES_HOST` | `localhost` | Host do Elasticsearch |

---

## 🌐 API REST

URL base: `http://localhost:8000/api/v1`  
Documentação interativa: `http://localhost:8000/docs`

### Autenticação

A plataforma usa **OAuth2 Password Bearer** (JWT). Todos os endpoints, exceto `/health` e `/auth/*`, exigem um token válido.

#### Registrar usuário

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "username": "analista",
  "email": "analista@empresa.com.br",
  "password": "Senha@Forte123!"
}
```

#### Login

```http
POST /api/v1/auth/token
Content-Type: application/x-www-form-urlencoded

username=analista&password=Senha@Forte123!
```

Resposta:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

Use o token em todas as requisições seguintes:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

### Alvos (Targets)

| Método | Endpoint | Descrição |
|---|---|---|
| `POST` | `/targets` | Criar novo alvo |
| `GET` | `/targets` | Listar todos os alvos (paginado) |
| `GET` | `/targets/{id}` | Detalhes do alvo |
| `PATCH` | `/targets/{id}` | Atualizar metadados do alvo |
| `DELETE` | `/targets/{id}` | Arquivar alvo |

#### Criar Alvo

```http
POST /api/v1/targets
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Empresa Exemplo",
  "value": "exemplo.com.br",
  "target_type": "domain",
  "description": "Domínio principal — autorizado para avaliação Q1"
}
```

Valores de `target_type`: `domain` | `ip` | `network` | `cloud` | `url`

---

### Scans

| Método | Endpoint | Descrição |
|---|---|---|
| `POST` | `/scan` | Iniciar scan completo ou por módulo |
| `GET` | `/scan` | Listar todos os scans do usuário atual |
| `GET` | `/scan/{id}` | Status do scan e resultados completos |
| `DELETE` | `/scan/{id}` | Cancelar scan em andamento |
| `GET (WS)` | `/scan/{id}/stream` | WebSocket — streaming ao vivo dos eventos |
| `GET` | `/modules` | Listar todos os módulos registrados |

#### Iniciar Scan Completo (todos os 7 módulos)

```http
POST /api/v1/scan
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_id": "96805e0d-3f92-4098-ae50-c6c5c2692e5a"
}
```

#### Iniciar Scan Direcionado (módulos específicos)

```http
POST /api/v1/scan
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_id": "96805e0d-3f92-4098-ae50-c6c5c2692e5a",
  "modules": ["dns_enumeration", "port_scanner", "web_analyzer"]
}
```

#### Formato do Resultado de Scan

```json
{
  "id": "9c3d3faf-3dd6-41f5-a10b-a168f813fb9f",
  "target_id": "96805e0d-3f92-4098-ae50-c6c5c2692e5a",
  "scan_type": "full",
  "status": "completed",
  "started_at": "2026-03-16T00:26:18.728431",
  "completed_at": "2026-03-16T00:26:49.622040",
  "risk_score": 4.0,
  "results": {
    "target": "exemplo.com.br",
    "modules_run": ["dns_enumeration", "port_scanner", "web_analyzer", "..."],
    "results": {
      "dns_enumeration": {
        "status": "success",
        "data": {
          "records": {
            "A": ["104.18.27.120", "104.18.26.120"],
            "NS": ["ns1.cloudflare.com.", "..."],
            "MX": ["10 mail.exemplo.com.br."],
            "TXT": ["v=spf1 include:_spf.google.com ~all"]
          }
        }
      }
    }
  }
}
```

#### Streaming ao Vivo (WebSocket)

Conecte-se ao endpoint WebSocket para receber eventos em tempo real conforme cada módulo é concluído:

```javascript
const ws = new WebSocket("ws://localhost:8000/api/v1/scan/<scan-id>/stream");
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // { "event": "module_complete", "module": "dns_enumeration", "status": "success" }
};
```

---

### Relatórios

| Método | Endpoint | Descrição |
|---|---|---|
| `POST` | `/reports` | Gerar relatório a partir de um scan concluído |
| `GET` | `/reports` | Listar todos os relatórios |
| `GET` | `/reports/{id}` | Metadados do relatório |
| `GET` | `/reports/{id}/download` | Baixar o arquivo do relatório |

#### Gerar Relatório HTML

```http
POST /api/v1/reports
Authorization: Bearer <token>
Content-Type: application/json

{
  "scan_result_id": "9c3d3faf-3dd6-41f5-a10b-a168f813fb9f",
  "format": "html",
  "title": "Q1 2026 — Avaliação Externa Empresa Exemplo"
}
```

Valores de `format`: `html` | `json`

---

## 💻 CLI — Linha de Comando

Instale o entry point da CLI (instalação editável):

```bash
pip install -e .
# ou simplesmente:
python -m cli.cli --help
```

### Alvos

```bash
# Adicionar alvo
security targets add exemplo.com.br --name "Empresa Exemplo" --type domain

# Listar alvos
security targets list

# Ver detalhes de um alvo
security targets show <id-do-alvo>

# Remover (arquivar) alvo
security targets delete <id-do-alvo>
```

### Scans

```bash
# Scan completo (todos os módulos)
security scan run exemplo.com.br

# Somente descoberta (DNS + subdomínios)
security scan discover exemplo.com.br

# Somente análise de rede (portas + fingerprinting)
security scan analyze exemplo.com.br

# Listar módulos disponíveis
security scan modules
```

### Relatórios

```bash
# Gerar relatório JSON
security report generate <id-do-scan>

# Gerar relatório HTML
security report generate <id-do-scan> --format html

# Listar relatórios gerados
security report list
```

### Plataforma

```bash
# Iniciar servidor da API
security serve

# Iniciar worker Celery (todas as filas)
security worker

# Iniciar Flower (monitoramento)
security flower

# Versão da plataforma
security version
```

---

## 🔌 Módulos de Segurança

Cada módulo é uma classe Python que herda de `SecurityModule` e implementa um único método assíncrono `run()`. O **PluginLoader** auto-descobre todas as subclasses concretas na inicialização — nenhum registro manual é necessário.

### Interface do Módulo

```python
from modules.base_module import SecurityModule, ModuleResult, ModuleStatus

class MeuModulo(SecurityModule):
    name = "meu_modulo"
    category = "custom"

    async def run(self, target: str, **kwargs) -> ModuleResult:
        # ... sua lógica aqui ...
        return ModuleResult(
            module_name=self.name,
            target=target,
            status=ModuleStatus.SUCCESS,
            data={"encontrado": ["..."]},
            metadata={"duracao_ms": 1234},
        )
```

### Como Adicionar um Novo Módulo

1. Crie um novo arquivo `.py` em qualquer lugar dentro de `modules/`
2. Herde de `SecurityModule` e defina `name` e `category`
3. Implemente `async run(target, **kwargs) -> ModuleResult`
4. Reinicie o servidor — o módulo é descoberto automaticamente

### Detalhes dos Módulos Integrados

#### `dns_enumeration` — Descoberta
Consulta todos os tipos de registro DNS padrão para o domínio alvo.

**Dados retornados:**
- `records` — dict de tipo de registro → lista de valores (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`)
- `assets` — lista de IPs e hostnames descobertos

#### `subdomain_discovery` — Descoberta
Enumeração passiva de subdomínios usando wordlist interna e feeds de transparência de certificados.

**Dados retornados:**
- `subdomains` — lista de subdomínios descobertos
- `assets` — ativos de subdomínio resolvidos com endereços IP

#### `port_scanner` — Rede
Scanner TCP assíncrono. Verifica as 1000 portas mais comuns por padrão.

**Dados retornados:**
- `open_ports` — lista de `{ port, protocol, state }`
- `host_alive` — boolean

#### `service_fingerprint` — Rede
Conecta às portas abertas e realiza banner grabbing e identificação de protocolo.

**Dados retornados:**
- `services` — lista de `{ port, service_name, product, version, banner }`

#### `dns_osint` — OSINT
Analisa registros DNS de segurança de e-mail e configuração da zona.

**Verificações realizadas:**
- Presença e rigor do registro SPF
- Política DMARC (none / quarantine / reject)
- Sondagem de seletores DKIM
- Registros CAA
- Validação DNSSEC

#### `web_analyzer` — Web
Realiza requisição HTTP/HTTPS e analisa a postura de segurança da resposta.

**Verificações realizadas:**
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- Flags `Secure` e `HttpOnly` dos cookies
- Política `Access-Control-Allow-Origin` (CORS)
- Validade do certificado TLS

#### `cloud_discovery` — Nuvem
Detecta delegação de serviços em nuvem via inspeção de CNAME em mais de 20 provedores.

**Detecta:** AWS (S3, CloudFront, ELB), Azure, GCP, Cloudflare, Fastly e outros.

---

## 🧠 Motor de Inteligência

### Correlação de CVEs (`cve_intelligence.py`)

Após a conclusão do scan, o worker de análise cruza as versões de serviço descobertas com:
1. Um **dataset de CVEs embutido** cobrindo as vulnerabilidades mais críticas (offline, sempre disponível)
2. A **API NIST NVD** para advisories atualizados (requer acesso à internet; ignorado graciosamente se indisponível)

Cada CVE correlacionado inclui: CVE-ID, score CVSS, severidade, produto/versão afetada e referências.

### Pontuação de Risco (`risk_engine.py`)

Produz uma **nota de risco composta de 0,0 a 10,0** a partir de três sub-notas:

| Componente | Peso | Fatores |
|---|---|---|
| Pontuação de Vulnerabilidade | 60% | Scores CVSS dos CVEs encontrados (amortecimento logarítmico) |
| Pontuação de Exposição | 40% | Portas de alto risco abertas (22, 23, 445, 3389, etc.) |
| Penalidade de Configuração | subtraída | Cabeçalhos HTTP ausentes, TLS fraco, CORS aberto |

**Níveis de Risco:**

| Pontuação | Nível |
|---|---|
| 0,0 – 2,9 | 🟢 Mínimo |
| 3,0 – 4,9 | 🔵 Baixo |
| 5,0 – 6,9 | 🟡 Médio |
| 7,0 – 8,9 | 🟠 Alto |
| 9,0 – 10,0 | 🔴 Crítico |

---

## 📄 Relatórios

### Relatório HTML

Um relatório HTML estilizado com tema escuro contendo:
- Visão geral do alvo e metadados do scan
- Badge de pontuação de risco com rótulo de nível
- Detalhamento do risco (sub-notas de vulnerabilidade / exposição / configuração)
- Descobertas OSINT e observações
- Recomendações de remediação priorizadas
- Resultados brutos dos módulos (recolhíveis)

Os relatórios gerados são salvos em `reports_output/` com a convenção de nomenclatura:  
`report_<prefixo-scan-id>_<timestamp>.html`

### Relatório JSON

Dump completo legível por máquina de todos os resultados em `reports_output/report_<id>_<ts>.json`.

### Download via API

```bash
curl http://localhost:8000/api/v1/reports/<id-do-relatorio>/download \
  -H "Authorization: Bearer <token>" \
  --output meu_relatorio.html
```

---

## 🔧 Desenvolvimento

### Executar Testes

```bash
pytest tests/ -v --cov=. --cov-report=term-missing
```

### Servidor com Hot Reload

```bash
uvicorn api.server:app --host 127.0.0.1 --port 8000 --reload
```

### Migrações de Banco de Dados (Alembic)

```bash
# Criar nova migração após alterar models.py
alembic revision --autogenerate -m "descreva sua alteração"

# Aplicar migrações
alembic upgrade head

# Reverter um passo
alembic downgrade -1
```

### Estilo de Código

```bash
# Formatação
black .

# Linting
ruff check .

# Verificação de tipos
mypy .
```

### Adicionar Dependências

```bash
pip install <pacote>
# Atualize requirements.txt manualmente ou:
pip freeze > requirements.txt
```

---

## 🔐 Segurança em Produção

### Checklist para Produção

- [ ] **Troque todos os segredos padrão** — gere `SECURITY_SECRET_KEY` com `python -c "import secrets; print(secrets.token_hex(32))"`
- [ ] **Defina senhas fortes** para DB e Redis no `.env`
- [ ] **Configure `SECURITY_ALLOWED_HOSTS`** com seus domínios reais, não `["*"]`
- [ ] **Configure `SECURITY_CORS_ORIGINS`** com a origem do seu frontend, não `["*"]`
- [ ] **Defina `DEBUG=false`** — desativa `/docs` e `/redoc` em produção
- [ ] **Defina `ENVIRONMENT=production`** — desativa a auto-migração na inicialização
- [ ] **Execute as migrações Alembic** manualmente antes de fazer deploy
- [ ] **Use TLS/HTTPS** — coloque a API atrás de nginx ou load balancer com terminação TLS
- [ ] **Restrinja o acesso de rede** — exponha apenas as portas 80/443 externamente; serviços internos (DB, Redis) não devem ser acessíveis pela internet
- [ ] **Ative autenticação no Redis** — defina `REDIS_PASSWORD`
- [ ] **Revise a política CORS** — nunca permita `*` em produção

### Controles de Segurança Integrados

- **TrustedHostMiddleware** — rejeita requisições com headers `Host` inesperados
- **Restrição CORS** — origens controladas via configuração, não hardcoded
- **Hashing de senhas** — bcrypt com salts por usuário (biblioteca `bcrypt` direta)
- **Expiração JWT** — configurável, padrão de 60 minutos
- **Nenhum segredo no código** — todos os segredos via variáveis de ambiente ou `.env` (excluído do git)
- **Queries parametrizadas** — todo acesso ao banco via ORM SQLAlchemy (sem risco de SQL injection)

---

## 🛠️ Solução de Problemas

### `pip install` falha em `psycopg2-binary`

Os headers de desenvolvimento do PostgreSQL não estão instalados. Opções:
- Instalar pacote dev do PostgreSQL: `apt install libpq-dev` (Debian/Ubuntu) ou `brew install postgresql` (macOS)
- Ou usar SQLite para desenvolvimento: `DATABASE_URL=sqlite+aiosqlite:///./dev.db`

### Servidor não inicia — porta em uso

```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <pid> /F

# Linux / macOS
lsof -ti:8000 | xargs kill -9
```

### `RuntimeError: This event loop is already running`

Pode ocorrer ao usar o modo eager do Celery (`CELERY_TASK_ALWAYS_EAGER=true`) dentro do loop de eventos do FastAPI. A plataforma trata isso automaticamente via padrão `ThreadPoolExecutor` nos workers.

### Scan travado no status `running` / `pending` (produção)

O worker Celery pode ter travado. Verifique:
```bash
# Docker Compose
docker compose logs worker-scan

# Celery direto
celery -A workers.worker_manager.celery_app inspect active
```

### `401 Unauthorized` em todas as requisições

Seu token JWT expirou. Faça login novamente com `POST /api/v1/auth/token`.

### `500 Internal Server Error` ao gerar relatório

Verifique o console do servidor para o traceback Python. Causas comuns:
- O `status` do scan não é `completed` — só scans concluídos podem ter relatórios gerados
- O `scan_result_id` não existe ou pertence a outro usuário

### Banco de dados fora de sincronia com as migrations

```bash
alembic current       # mostra a revisão atual
alembic upgrade head  # aplica todas as migrações pendentes
```

---

## 📜 Licença

Este projeto está licenciado sob a **Licença MIT**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## ⚖️ Uso Legal e Ético

Este software é fornecido **somente para testes de segurança legítimos e autorizados**.

**Você deve:**
- Escanear apenas sistemas que você possui ou para os quais possui **autorização explícita e por escrito**
- Cumprir toda a legislação aplicável (Lei nº 12.737/2012 — Lei Carolina Dieckmann, LGPD, Marco Civil da Internet, etc.)
- Praticar divulgação responsável caso vulnerabilidades sejam descobertas em sistemas de terceiros

**Você não deve:**
- Usar esta ferramenta contra sistemas sem autorização
- Usar os resultados dos scans para atacar, prejudicar ou extorquir
- Contornar controles de acesso

Os autores não aceitam nenhuma responsabilidade pelo uso indevido desta ferramenta. **Use com responsabilidade.**

---

<div align="center">

Construído para profissionais de segurança, por profissionais de segurança. 🇧🇷

</div>
