# Runbook — Força bruta / credential stuffing no login da TaskFlow

**Base:** NIST SP 800-61 Rev. 2 (as quatro fases do ciclo de resposta a incidentes).
**Dono:** grupo DevSecOps · **Severidade padrão:** Média (Alta se houver login bem-sucedido após a rajada).
**Exercitado em:** 16/11/2026, ambiente local (`docker compose`), evidência em [`evidencias/incidente/deteccao-loki.txt`](evidencias/incidente/deteccao-loki.txt) (API do Loki) e [`evidencias/incidente/grafana-forca-bruta.jpg`](evidencias/incidente/grafana-forca-bruta.jpg) (dashboard: T1 com 44 falhas/min de um IP, T2 com o login bem-sucedido em seguida).

---

## Condição de disparo

| Gatilho | Query LogQL (painel do Grafana) | Limiar |
|---|---|---|
| **T1 — rajada de falhas** | `sum by (ip) (count_over_time({job="taskflow", event="login_attempt", result="failure"} \| json [1m]))` (painel **Q1**) | **> 20 falhas por IP em 1 min** |
| **T2 — conta possivelmente comprometida** | `sum by (ip) (count_over_time({job="taskflow", event="login_attempt", result="success"} \| json [5m]))` (painel **Q4**) cruzado com Q1 | **≥ 1 sucesso do mesmo IP que disparou T1 nos últimos 5 min** → severidade **Alta** |

Por que 20/min: um usuário legítimo que esqueceu a senha erra 3–5 vezes; o script de força bruta faz dezenas por minuto. O limiar fica acima do erro humano e bem abaixo do ataque automatizado.

---

## Fase 1 — Preparação

- [x] A aplicação registra todo `login_attempt` em JSON com `result`, `username`, `ip` e `request_id`, **sem a senha** (teste automatizado `test_senha_nunca_vai_para_o_log`).
- [x] Promtail envia o log ao Loki; `event`, `level` e `result` são labels para consulta rápida.
- [x] Dashboard **TaskFlow - Segurança** provisionado no Grafana, com o limiar de T1 desenhado no gráfico.
- [x] Simulador de ataque para treino: `python scripts/forca_bruta.py` (recusa qualquer alvo que não seja localhost).
- [x] Segredo de sessão em variável de ambiente (`TASKFLOW_SECRET_KEY`): pode ser rotacionado sem build, o que permite invalidar todas as sessões na contenção.

## Fase 2 — Detecção e análise

1. Abrir o Grafana → **TaskFlow - Segurança**. O painel **Q1** mostra a linha de um IP acima do limiar vermelho.
2. Confirmar o IP e o alvo:
   ```logql
   sum by (ip, username) (count_over_time({job="taskflow", event="login_attempt", result="failure"} | json [5m]))
   ```
3. Verificar se houve sucesso depois da rajada (T2) — painel **Q4**, ou:
   ```logql
   {job="taskflow", event="login_attempt", result="success"} | json | ip="<IP>"
   ```
4. Se houve sucesso, reconstruir o que a sessão fez a partir do `request_id` e do usuário:
   ```logql
   {job="taskflow"} | json | user="<usuario>" | line_format "{{.timestamp}} {{.method}} {{.path}} {{.status_code}}"
   ```
5. Registrar: janela de tempo, IP(s), conta(s)-alvo, número de tentativas, se houve sucesso e quais ações a sessão executou.

**No exercício de 16/11:** Q1 mostrou **58 falhas em 10 min** do IP `172.20.0.1` contra `admin`, e Q4 mostrou **2 logins bem-sucedidos** do mesmo IP (a senha de laboratório estava na lista do atacante) → **severidade Alta**.

## Fase 3 — Contenção, erradicação e recuperação

| Passo | Ação | Como, neste ambiente |
|---|---|---|
| Contenção curta | Bloquear o IP de origem | Regra de firewall no host/borda (em produção: WAF ou security group). No lab, o tráfego vem do gateway Docker, então a contenção vai para a conta (próximo passo) |
| Contenção da conta | Derrubar **todas** as sessões existentes | Rotacionar o segredo e recriar o serviço: novo `TASKFLOW_SECRET_KEY` no `.env` → `docker compose up -d taskflow`. Cookies assinados com a chave antiga deixam de valer |
| Erradicação | Trocar a senha da conta-alvo e revisar o que a sessão do atacante criou | `UPDATE users SET password = <novo hash>` via script administrativo; apagar tarefas criadas pelo atacante (identificadas pelo `request_id` na Fase 2) |
| Recuperação | Voltar ao normal com monitoramento reforçado | Acompanhar Q1/Q4 por 24 h; o mesmo IP voltando é tratado como incidente novo |

## Fase 4 — Atividade pós-incidente

- **Causa-raiz:** senha fraca da conta de laboratório **e** ausência de limitação de tentativas no `/login` (decisão consciente nesta versão, para que o ataque fosse observável; ver README, decisões).
- **Ações de melhoria (com dono e prazo, viram issues):**
  1. Rate limiting por IP e por conta no `/login` (ex.: Flask-Limiter, 5 tentativas/min) e atraso progressivo.
  2. Bloqueio temporário da conta após N falhas, com aviso ao dono.
  3. Alerta automático do Grafana para T1 e T2 (hoje a detecção depende de alguém olhar o painel).
  4. Política de senha forte e MFA para contas administrativas.
- **Lições:** o log estruturado permitiu responder em minutos "quem, de onde, quantas vezes e se entrou"; sem `ip` e `result` no evento, a rajada seria só um monte de `200 /login` no access log.
