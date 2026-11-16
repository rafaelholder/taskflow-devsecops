"""Cada teste prova que uma vulnerabilidade da linha de base continua corrigida."""

import json

from conftest import token_de


def test_login_valido(login):
    assert login().status_code == 302


def test_sql_injection_no_login_nao_autentica(login):
    # Na linha de base, "admin' --" comentava a checagem de senha e entrava como admin.
    resposta = login(usuario="admin' --", senha="qualquer")
    assert resposta.status_code == 200
    assert "Usuario ou senha invalidos" in resposta.get_data(as_text=True)


def test_sql_injection_na_busca_nao_quebra_nem_vaza(client, login):
    login()
    resposta = client.get("/tasks", query_string={"q": "' OR '1'='1"})
    assert resposta.status_code == 200
    assert "Nenhuma tarefa encontrada" in resposta.get_data(as_text=True)


def test_xss_armazenado_e_escapado(client, login):
    login()
    token = token_de(client.get("/tasks/new").get_data(as_text=True))
    client.post(
        "/tasks/new",
        data={
            "title": "<b>titulo</b>",
            "description": "<img src=x onerror=alert(1)>",
            "csrf_token": token,
        },
    )
    html = client.get("/tasks").get_data(as_text=True)
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_xss_refletido_no_parametro_q(client, login):
    login()
    html = client.get("/tasks", query_string={"q": '"><svg/onload=alert(1)>'}).get_data(
        as_text=True
    )
    assert "<svg/onload" not in html


def test_debug_info_removido(client):
    assert client.get("/debug/info").status_code == 404


def test_post_sem_token_csrf_e_recusado(client):
    resposta = client.post("/login", data={"username": "admin", "password": "admin123"})
    assert resposta.status_code == 400


def test_cabecalhos_de_seguranca(client):
    h = client.get("/login").headers
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["Cross-Origin-Embedder-Policy"] == "require-corp"
    assert "X-Request-ID" in h


def test_cookie_de_sessao_httponly_samesite(client):
    cookie = client.get("/login").headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_senha_nunca_vai_para_o_log(login, log_file):
    login(usuario="admin", senha="senha-que-nao-pode-aparecer-123")
    conteudo = log_file.read_text(encoding="utf-8")
    assert "senha-que-nao-pode-aparecer-123" not in conteudo
    eventos = [json.loads(linha) for linha in conteudo.splitlines()]
    falhas = [e for e in eventos if e.get("event") == "login_attempt" and e["result"] == "failure"]
    assert falhas, "falha de login deveria gerar evento"
    assert {"ip", "username", "request_id"} <= falhas[-1].keys()


def test_senhas_guardadas_com_hash():
    import app as taskflow

    with taskflow.app.app_context():
        senha = (
            taskflow.get_db()
            .execute("SELECT password FROM users WHERE username = 'admin'")
            .fetchone()["password"]
        )
    assert senha != "admin123"
    assert senha.startswith(("scrypt:", "pbkdf2:"))
