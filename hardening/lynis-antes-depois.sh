#!/usr/bin/env bash
# Encontro 3: Lynis no container da aula (ubuntu:22.04 + Passos 0-6) antes e depois de
# corrigir os 3 achados de maior severidade (os Warnings). Saida em docs/evidencias/lynis/.
set -euo pipefail
cd "$(dirname "$0")"
saida=../docs/evidencias/lynis
mkdir -p "$saida"

docker build -q --target encontro3 -t lynis:encontro3 -f Dockerfile.lynis . >/dev/null
docker build -q --target depois    -t lynis:depois    -f Dockerfile.lynis . >/dev/null

docker run --rm lynis:encontro3 > "$saida/lynis-antes.txt" 2>&1 || true
# NET_ADMIN: necessario para o ufw criar regras; afeta so o namespace de rede do container.
docker run --rm --cap-add=NET_ADMIN lynis:depois > "$saida/lynis-depois.txt" 2>&1 || true

for alvo in antes depois; do
  printf '%-7s %s | %s\n' "$alvo" \
    "$(grep -m1 'Hardening index' "$saida/lynis-$alvo.txt" | sed -E 's/.*: ([0-9]+).*/indice \1/')" \
    "$(grep -m1 -E 'Warnings \(' "$saida/lynis-$alvo.txt" | sed -E 's/^\s+//')"
done
echo "Warnings tratados (1 = presente):"
for id in PKGS-7392 FIRE-4512 LOGG-2138; do
  printf '  %-10s antes=%s depois=%s\n' "$id" \
    "$(grep -cE "^\s+! .*\[$id\]" "$saida/lynis-antes.txt" || true)" \
    "$(grep -cE "^\s+! .*\[$id\]" "$saida/lynis-depois.txt" || true)"
done
