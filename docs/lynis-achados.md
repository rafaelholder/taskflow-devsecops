# Lynis — os 3 achados de maior severidade (Encontro 3)

**Ambiente:** o mesmo da aula — container `ubuntu:22.04` com os Passos 0 a 6 aplicados (usuário `aluno` com sudo, root bloqueado, política do ufw, fail2ban no SSH, `sshd_config` endurecido do material da disciplina, permissões do diretório da aplicação). Definido em [`hardening/Dockerfile.lynis`](../hardening/Dockerfile.lynis), estágio `encontro3`. Reprodução: `bash hardening/lynis-antes-depois.sh`.

**Critério de severidade:** o Lynis separa **Warnings** (achados que exigem ação) de **Suggestions** (melhorias). Ao fim do Encontro 3 havia **exatamente 3 Warnings** — são eles os 3 de maior severidade.

| | Antes (fim da aula) | Depois |
|---|---|---|
| Warnings | **3** | **0** ("Great, no warnings") |
| Hardening index | 61 | 62 |
| Testes executados | 234 | 234 |

Evidência: [`evidencias/lynis/lynis-antes.txt`](evidencias/lynis/lynis-antes.txt) e [`lynis-depois.txt`](evidencias/lynis/lynis-depois.txt).

## 1. PKGS-7392 — "Found one or more vulnerable packages"

**Risco.** Pacotes do sistema com vulnerabilidades já corrigidas pelo fornecedor: o caminho mais barato para um atacante é explorar uma CVE pública.
**Correção.** `apt-get upgrade -y` no estágio `depois` (CIS Ubuntu 22.04, 1.9 — atualizações de segurança aplicadas).
**Na esteira da TaskFlow:** é o mesmo princípio do gate do Trivy (CVE com correção disponível bloqueia) e do upgrade pontual do zlib no `Dockerfile` da aplicação.

## 2. FIRE-4512 — "iptables module(s) loaded, but no rules active"

**Risco.** O Passo 3 configurou a política do ufw (negar entrada, liberar só o SSH), mas ela **existia só em arquivo**: nenhuma regra estava carregada no netfilter. Firewall configurado e não ativo é a pior combinação, porque dá falsa sensação de proteção.
**Correção.** O ponto de entrada `hardening/auditar.sh` executa `ufw --force enable` antes da auditoria; o Lynis passa a ver o firewall **ACTIVE** e as políticas das chains. O container recebe só a capability `NET_ADMIN`, que altera exclusivamente o namespace de rede dele (CIS Ubuntu 22.04, 3.5 — firewall configurado e ativo).

## 3. LOGG-2138 — "klogd is not running"

**Risco.** Sem daemon de log, eventos do sistema (autenticação, sudo, sshd, fail2ban) não ficam registrados: um incidente aconteceria sem rastro para a resposta.
**Correção.** Instalação do `rsyslog` e inicialização no `auditar.sh`; o Lynis passa a encontrar o RSyslog ativo (CIS Ubuntu 22.04, 4.2.1 — rsyslog instalado e em execução).
**Limitação declarada:** dentro de container, o módulo `imklog` não lê `/proc/kmsg` (o log do kernel pertence ao host), então o rsyslog registra os eventos do sistema mas não as mensagens do kernel. Em VM ou servidor físico o mesmo pacote cobre as duas coisas.

## Por que o índice subiu pouco (61 → 62)

O índice pondera dezenas de testes; os três corrigidos são poucos em número, mas são os únicos classificados como Warning. As 39 sugestões restantes (partições separadas para `/home` e `/var`, módulos de kernel `dccp`/`sctp`, banner legal, `libpam-tmpdir`, idade de senha etc.) ficam como backlog de hardening — várias não se aplicam a container (partições, drivers USB/firewire).
