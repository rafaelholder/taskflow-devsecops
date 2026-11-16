#!/usr/bin/env bash
# Roda o Lynis no container Ubuntu antes e depois do hardening e compara os achados tratados.
set -euo pipefail
cd "$(dirname "$0")"
saida=../docs/evidencias/lynis
mkdir -p "$saida"

for alvo in antes depois; do
  docker build -q --target "$alvo" -t "lynis:$alvo" -f Dockerfile.lynis . >/dev/null
  docker run --rm "lynis:$alvo" > "$saida/lynis-$alvo.txt" 2>&1 || true
done

echo "Indice de hardening:"
for alvo in antes depois; do
  printf '  %-7s %s\n' "$alvo" "$(grep -m1 'Hardening index' "$saida/lynis-$alvo.txt" | sed -E 's/.*: ([0-9]+).*/\1/')"
done

echo "Achados tratados (1 = presente):"
for id in AUTH-9328 AUTH-9230 AUTH-9286 KRNL-5820 DEB-0280 PKGS-7370; do
  printf '  %-10s antes=%s depois=%s\n' "$id" \
    "$(grep -c "\[$id\]" "$saida/lynis-antes.txt" || true)" \
    "$(grep -c "\[$id\]" "$saida/lynis-depois.txt" || true)"
done
