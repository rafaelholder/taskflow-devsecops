# Roteiro da apresentação (27/11 · 30 min · sem slides)

Mostrar **o repositório, os PRs e a aba Actions**. Plano B: prints em `docs/evidencias/` e um vídeo curto gravado antes.

| Min | Bloco | Quem ⚠️ | O que mostrar |
|---|---|---|---|
| 0–2 | Contexto | | Grupo, papéis, o que é a TaskFlow e as 6 falhas da linha de base (commit `92e4193`) |
| 2–8 | **Demo shift-left** | | Abrir o PR `demo/sqli-regressao` (query concatenada). Checks rodando → **Semgrep vermelho** (`tainted-sql-string` + regra própria `taskflow-sql-concatenado`) → merge bloqueado. Push da correção → verde → merge |
| 8–12 | Antes × depois | | Tabela do README: Trivy 504 HIGH + 15 CRITICAL → 0 com correção; Semgrep 10 → 0; pip-audit 51 → 0; `docker history` com `ENV ADMIN_PASSWORD` → sem segredo; Lynis do Encontro 3: 3 Warnings → 0 (`docs/lynis-achados.md`); tabela dos 8 alertas do ZAP → A05; print do Grafana na seção 6 |
| 12–17 | **Demo DAST** | | Aba Actions → job do ZAP: app subindo no runner, espera ativa pelo `/login`, relatório no artefato. Explicar o `rules.tsv` (3 IGNORE + 1 INFO, cada um justificado). Mapa OWASP Top 10 |
| 17–20 | IaC | | Checkov: `main.insecure.tf` com 16 falhas → `infra/main.tf` com 0 (6 skips justificados). Trivy config achou o egress `0.0.0.0/0` que o arquivo de referência deixava passar |
| 20–27 | **Incidente ao vivo** | | `docker compose up -d` → `python scripts/forca_bruta.py --acertar` → Grafana, painel Q1 acima do limiar e Q4 com o login obtido → percorrer as 4 fases do runbook, incluindo a rotação do `TASKFLOW_SECRET_KEY` que derruba as sessões |
| 27–29 | Decisão técnica | | Trade-off: Trivy com `ignore-unfixed` (47 HIGH sem patch do Debian não bloqueiam; o que tem patch bloqueia — e por isso o zlib foi corrigido à mão) **ou** a ausência proposital de rate limiting para o ataque ser observável |
| 29–30 | Aprendizado | | O mais impactante para o grupo |

## Antes da apresentação

- [ ] `docker compose up -d` e conferir os 4 serviços `healthy`
- [ ] Rodar a força bruta uma vez para "esquentar" o Loki
- [ ] Branch `demo/sqli-regressao` pronta e PR aberto em rascunho
- [ ] Gravar o vídeo plano B (≈3 min: PR vermelho → verde, ZAP, Grafana)
- [ ] Todos sabem explicar qualquer job (a nota de apresentação exige que todos falem)
