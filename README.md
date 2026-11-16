# TaskFlow — esteira segura, DAST, IaC e observabilidade

[![CI](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/ci.yml/badge.svg)](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/ci.yml)
[![SAST e Secret Scanning](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/sast.yml/badge.svg)](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/sast.yml)
[![SCA](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/sca.yml/badge.svg)](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/sca.yml)
[![Hardening](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/hardening.yml/badge.svg)](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/hardening.yml)
[![DAST](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/dast.yml/badge.svg)](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/dast.yml)
[![IaC](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/iac-scan.yml/badge.svg)](https://github.com/rafaelholder/taskflow-devsecops/actions/workflows/iac-scan.yml)

Lab final de **DevSecOps (CS031) — CESAR School, 2026.2**. A TaskFlow, aplicação Flask vulnerável de propósito, passa a ser protegida por uma esteira no GitHub Actions que **bloqueia o merge** quando o código, as dependências, a imagem, a aplicação em execução ou a infraestrutura têm problemas; o ambiente sobe por Compose endurecido; e um ataque de força bruta é detectado no Grafana e tratado por um runbook.

**Grupo** ⚠️ *preencher nomes e papéis* · **Professores:** Cris Apolinário e Diego Buarque

O primeiro commit (`92e4193`) é a linha de base original da disciplina, intacta. Tudo depois dele é trabalho do grupo, então `git diff 92e4193` mostra exatamente o que mudou.

---

## 1. A esteira

Todos os workflows rodam em `pull_request` e `push` na `main`, têm `workflow_dispatch`, `permissions: contents: read` e **actions de terceiros fixadas por SHA de commit** (imagens por digest). Nenhum usa `continue-on-error`, `--exit-zero` ou `soft_fail`.

| Workflow | Job (= required check da `main`) | Gate: bloqueia o merge se… | Módulo |
|---|---|---|---|
| `ci.yml` | **Build, lint e testes** | dependência sem o hash esperado · `ruff check` (inclui regras de segurança `S`) · formatação · 11 testes de segurança falham | 1 |
| `sast.yml` | **SAST - Semgrep** | qualquer achado de `p/python`, `p/flask`, `p/security-audit` ou das 5 regras próprias (`.semgrep/taskflow.yml`) | 3 |
| `sast.yml` | **Secret scanning - Gitleaks** | segredo em **qualquer commit do histórico** (`fetch-depth: 0`) | 3 |
| `sca.yml` | **SCA - pip-audit** | CVE conhecida em dependência direta ou transitiva | 3 |
| `sca.yml` | **SCA - Trivy fs (segunda fonte)** | CVE HIGH/CRITICAL com correção, por outra base de dados | 3 |
| `hardening.yml` | **Build + Trivy + flags de runtime** | segredo em `ENV/ARG` nas camadas · `USER` ≠ `taskflow` · CVE HIGH/CRITICAL **com correção** na imagem · container não sobe com `--read-only --cap-drop=ALL --security-opt=no-new-privileges` | 2 |
| `dast.yml` | **ZAP Baseline contra a app no runner** | qualquer alerta do ZAP não rebaixado (com justificativa) em `.zap/rules.tsv` | 4 |
| `iac-scan.yml` | **IaC - Checkov (terraform + dockerfile + github_actions)** | falha do Checkov sem `checkov:skip` justificado | 5 |
| `iac-scan.yml` | **IaC - Trivy config (tfsec + compose + Dockerfile)** | configuração HIGH/CRITICAL | 5 |
| `iac-scan.yml` | **IaC - terraform validate** | Terraform inválido | 5 |

Fora do CI: **Dependabot** (pip, GitHub Actions e Docker, semanal), **CODEOWNERS** e template de PR.

**Proteção da `main`:** PR obrigatório com 1 aprovação de code owner, os 10 checks acima obrigatórios, branch atualizada antes do merge, histórico linear, sem force push, sem exclusão.

### Disparar cada workflow

Abrir um PR para a `main` dispara todos. Para rodar um isolado: **Actions → (workflow) → Run workflow**, ou `gh workflow run dast.yml`. O `sca.yml` também roda toda segunda-feira, porque CVE nova em dependência antiga aparece sem ninguém abrir PR.

> **Por que nenhum workflow usa filtro `paths:`** — os jobs são required checks. Um `iac-scan` que só rodasse quando um `.tf` muda deixaria todo PR de código travado esperando um check que nunca chega. Rodar sempre custa ~1 min por PR.

## 2. Onde cada ferramenta entra no S-SDLC

```mermaid
flowchart LR
    P["Plan<br/>threat model das 6 falhas<br/>CODEOWNERS · template de PR"] --> C["Code<br/>ruff (S)"]
    C --> B["Build<br/>pip --require-hashes<br/>Dockerfile multi-stage"]
    B --> T["Test<br/>pytest de segurança<br/>Semgrep · Gitleaks<br/>pip-audit · Trivy fs"]
    T --> R["Release<br/>Trivy image<br/>docker history sem segredo<br/>Checkov · Trivy config"]
    R --> D["Deploy<br/>Compose endurecido<br/>read_only · cap_drop · redes"]
    D --> O["Operate<br/>ZAP Baseline na app rodando<br/>Dependabot semanal"]
    O --> M["Monitor<br/>logs JSON + request_id<br/>Promtail → Loki → Grafana<br/>runbook NIST 800-61"]
    M -. "pós-incidente vira issue" .-> P
```

## 3. Arquitetura do ambiente (`docker-compose.yml`)

```mermaid
flowchart LR
    U(["Navegador<br/>127.0.0.1"]) -->|":5000"| APP
    U -->|":3000"| GRAF
    subgraph frontend["rede frontend"]
        APP["taskflow<br/>gunicorn · UID 10001<br/>read_only · cap_drop ALL"]
        GRAF["grafana"]
    end
    subgraph backend["rede backend (internal: sem saída, sem porta no host)"]
        PT["promtail"] --> LOKI[("loki")]
    end
    APP -- "logs JSON<br/>volume compartilhado (ro)" --> PT
    GRAF -- "LogQL" --> LOKI
    APP --- DB[("SQLite<br/>volume nomeado")]
```

- Só `taskflow` e `grafana` publicam porta, e **só em `127.0.0.1`**. O Loki (o banco de logs) fica numa rede `internal` sem porta no host.
- Todos os serviços: `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, limites de CPU e memória (e de PIDs na app), healthcheck e rotação de log.
- Segredos só no `.env` (fora do Git). O Compose **recusa subir** se `TASKFLOW_SECRET_KEY` ou `GRAFANA_ADMIN_PASSWORD` faltarem.

```bash
cp .env.example .env        # preencha com valores aleatórios
docker compose up -d --build
# app: http://127.0.0.1:5000 (admin/admin123 ou aluno/senha123, usuários de LABORATÓRIO)
# grafana: http://127.0.0.1:3000 → TaskFlow → "TaskFlow - Segurança"
python scripts/forca_bruta.py --acertar   # simula o ataque (só aceita localhost)
```

## 4. Antes × depois (medido)

| Ferramenta | Linha de base | Agora | Evidência (`docs/evidencias/`) |
|---|---|---|---|
| **Trivy image** (HIGH/CRITICAL) | SO: **504 HIGH + 15 CRITICAL** · Python: 12 HIGH + 3 CRITICAL | **0 com correção disponível** (47 HIGH do Debian sem patch publicado) | `trivy-antes.txt`, `trivy-depois.txt` |
| **docker history** | `ENV ADMIN_PASSWORD=admin123` gravado na camada | nenhum segredo; `USER taskflow` | `docker-history-antes.txt`, `-depois.txt` |
| **Semgrep** | **10 achados** (SQLi ×2, XSS, SECRET_KEY, retorno de f-string, debug) | **0** (+ 5 regras próprias) | `semgrep-antes.txt`, `semgrep-depois.txt` |
| **Gitleaks** | **0** com as regras padrão — **a SECRET_KEY passava despercebida** | regra própria pega o literal; allowlist só para o commit didático | `.gitleaks.toml` |
| **pip-audit** | **51 vulnerabilidades em 5 pacotes** (Flask 0.12.2, Werkzeug 0.15.4…) | **0** | `pip-audit-antes.txt`, `-depois.txt` |
| **OWASP ZAP** | **8 WARN** | **0 WARN · 0 FAIL · 64 PASS** (3 IGNORE + 1 INFO justificados) | `zap/zap-antes.*`, `zap/zap-depois.*` |
| **Checkov (Terraform)** | `main.insecure.tf`: **16 falhas** | **0** (6 skips justificados na linha) | `checkov-antes.txt`, `checkov-depois.txt` |
| **Trivy config** | o próprio `main.fixed.tf` de referência deixava **egress 443 para 0.0.0.0/0** (CRITICAL) | **0** | `trivy-config.txt` |
| **Lynis** (container Ubuntu) | índice **58** | índice **65**; 6 achados corrigidos | `lynis/` |

Provas de exploração na linha de base (rodando a versão original): `admin' --` no login entra **sem senha** (302 para `/tasks`); `/debug/info` devolve a página do **debugger interativo do Werkzeug**. Na versão atual: login recusado e `404`. E um bônus da FALHA 1: com `FROM python:latest` a imagem original **nem sobe mais** — o `latest` virou Python 3.15, incompatível com o Flask 0.12 (`falha1-python-latest-quebra.txt`).

## 5. As vulnerabilidades da TaskFlow, a correção e a prova

| # | Falha da linha de base | OWASP Top 10 (2021) | Correção | Quem impede a volta |
|---|---|---|---|---|
| 1 | SQL Injection no login e na busca | **A03** Injection | placeholders `?` | Semgrep (`tainted-sql-string` + `taskflow-sql-concatenado`), 2 testes |
| 2 | XSS armazenado na descrição; refletido em `q` e no erro do login | **A03** Injection | templates Jinja2 com autoescape, sem `\| safe`; CSP | regra `taskflow-template-safe-filter`, 2 testes, ZAP |
| 3 | `SECRET_KEY` no código | **A02** Cryptographic Failures · **A05** | variável obrigatória; a app não sobe sem ela | Gitleaks (regra própria), Semgrep |
| 4 | Senhas em texto puro | **A02** Cryptographic Failures | `generate_password_hash` (scrypt, com salt) | teste `test_senhas_guardadas_com_hash` |
| 5 | `/debug/info` e `debug=True` | **A05** Security Misconfiguration | rota removida; `FLASK_DEBUG` desligado por padrão; gunicorn | regra `taskflow-flask-debug-ligado`, teste, ZAP |
| 6 | Dependências com CVE | **A06** Vulnerable and Outdated Components | `requirements.in` → `requirements.txt` **com hashes**; PyYAML e requests removidos (não eram usados) | pip-audit, Trivy fs, Dependabot |
| — | Cabeçalhos ausentes, CSRF, cookie sem flags (achados do ZAP) | **A05** · **A01** | CSP, X-Frame-Options, nosniff, COOP/COEP/CORP, token CSRF sincronizador, cookie `HttpOnly`/`SameSite` | ZAP, 3 testes |
| — | Falhas 1–6 do Dockerfile | **A05** · **A08** Integrity | digest fixo, multi-stage, `--require-hashes`, UID 10001, sem `ENV` secreto, gunicorn, healthcheck | job de hardening |
| — | Sem logs de segurança | **A09** Logging & Monitoring Failures | JSON com `request_id`; eventos de login, tarefa, listagem e CSRF; nada sensível | teste `test_senha_nunca_vai_para_o_log`, regra `taskflow-formulario-inteiro-no-log` |

## 6. Observabilidade e resposta a incidente

Consultas LogQL do dashboard **TaskFlow - Segurança** (provisionado automaticamente):

| Pergunta | LogQL |
|---|---|
| **Q1** Quem está errando senha, e quanto? | `sum by (ip) (count_over_time({job="taskflow", event="login_attempt", result="failure"} \| json [1m]))` |
| **Q2** Quais contas estão sendo atacadas? | `sum by (username) (count_over_time({job="taskflow", event="login_attempt", result="failure"} \| json [5m]))` |
| **Q3** A aplicação está devolvendo erro? | `sum by (status_code) (count_over_time({job="taskflow", event="http_request"} \| json [1m]))` |
| **Q4** Alguém entrou depois da rajada? | `sum by (ip) (count_over_time({job="taskflow", event="login_attempt", result="success"} \| json [1m]))` |
| **Q5** Há varredura de payloads na busca? | `{job="taskflow", event="tasks_list_accessed"} \| json \| search=~".*(<\|>\|'\|--\|(?i)union\|(?i)select).*"` |

Runbook com condição de disparo, query de detecção e as quatro fases do NIST SP 800-61, já exercitado: **[docs/runbook-forca-bruta.md](docs/runbook-forca-bruta.md)**.

## 7. Decisões técnicas e trade-offs

1. **Trivy com `ignore-unfixed`.** A imagem base Debian tem 47 HIGH sem patch publicado. Bloquear por eles deixaria o gate permanentemente vermelho e, na prática, ignorado. O que **tem** correção bloqueia — foi assim que apareceu o CVE-2026-85091 do zlib, corrigido no Dockerfile com versão fixada até a imagem base ser atualizada.
2. **Sem rate limiting no `/login`, de propósito.** O Módulo 6 pede que a força bruta aconteça e seja detectada; limitar na aplicação esconderia o sinal. É a primeira ação pós-incidente do runbook.
3. **Rebaixamentos do ZAP só para o informativo.** 10049 é consequência do `Cache-Control: no-store` que nós mesmos colocamos; 10111 e 10112 são reconhecimento de formulário e de cookie. O 10031 ficou como INFO (aparece, não bloqueia) porque o valor refletido é o token CSRF do servidor. CSRF (10202) e COEP (90004) foram **corrigidos**, não ignorados.
4. **Gitleaks: allowlist por commit, não por regra.** O commit didático fica no histórico de propósito; a exceção é o hash dele, nunca a regra inteira.
5. **`hardening/` fora só do Trivy config.** O container do Lynis precisa de root para auditar o SO. O Checkov continua escaneando a pasta com skips justificados, e a imagem da aplicação segue obrigada a rodar como `taskflow`.
6. **Dependências mínimas.** PyYAML e requests saíram: não eram importados, e duas das cinco bibliotecas com CVE da linha de base eram elas.

## 8. Demonstração do shift-left

Branch `demo/sqli-regressao`: reintroduz uma query concatenada na busca. O PR fica com **SAST - Semgrep** vermelho e o merge bloqueado; o commit seguinte volta a usar `?` e tudo fica verde. Roteiro completo da apresentação: **[docs/roteiro-apresentacao.md](docs/roteiro-apresentacao.md)**.

## 9. Estrutura

```text
app.py · templates/           aplicação corrigida e instrumentada
Dockerfile · .dockerignore     imagem endurecida (Módulo 2)
requirements.in → .txt         dependências diretas → travadas com hashes
tests/                         11 testes de segurança (pytest)
.semgrep/taskflow.yml          5 regras próprias
.gitleaks.toml                 regra da SECRET_KEY + allowlist do commit didático
.zap/rules.tsv                 exceções do DAST, cada uma justificada
.github/workflows/             ci · sast · sca · hardening · dast · iac-scan
.github/dependabot.yml · CODEOWNERS · pull_request_template.md
docker-compose.yml · .env.example
observabilidade/               promtail + provisionamento do Grafana (datasource e dashboard)
infra/main.tf                  Terraform corrigido (validate + Checkov + Trivy config)
hardening/                     Lynis antes × depois
scripts/forca_bruta.py         simulador de ataque (só localhost)
docs/                          runbook, roteiro, evidências antes × depois
```
