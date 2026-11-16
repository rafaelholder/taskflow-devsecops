#!/bin/sh
# Ponto de entrada do estagio "depois": liga o que precisa estar RODANDO para o Lynis medir.
set -e
rsyslogd                       # LOGG-2138: syslog/kernel logger ativo
ufw --force enable >/dev/null  # FIRE-4512: politica do Passo 3 vira regra ativa no netfilter
exec lynis audit system --quick --no-colors
