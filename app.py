"""
TaskFlow - versao endurecida e instrumentada.

Partiu da linha de base vulneravel (commit inicial deste repositorio) e corrige, com
referencia ao modulo da disciplina em que cada item foi tratado:

  Modulo 3 (SAST / secret scanning)
    - SQL Injection no login e na busca -> consultas parametrizadas ("?")
    - SECRET_KEY no codigo               -> variavel de ambiente obrigatoria (sem fallback)
    - senhas em texto puro               -> hash com salt (werkzeug.security)
  Modulo 4 (DAST)
    - XSS armazenado e refletido         -> templates Jinja2 com autoescape, sem "| safe"
                                            (descricao, titulo, parametro q e erro do login)
    - /debug/info                        -> removido
    - debug=True                         -> FLASK_DEBUG, desligado por padrao
    - cabecalhos de seguranca            -> CSP, X-Frame-Options, nosniff, Referrer-Policy,
                                            Permissions-Policy, Cache-Control: no-store
    - cookie de sessao                   -> HttpOnly + SameSite=Lax (+ Secure via variavel)
  Modulo 6 (observabilidade)
    - logging estruturado em JSON (uma linha por evento) em stdout e em arquivo
    - request_id (UUID v4) por requisicao, presente em todo log daquela requisicao
    - eventos: http_request, login_attempt (success/failure), logout,
               task_created, tasks_list_accessed
    - nunca se loga senha, token ou cookie; o corpo do formulario nao e logado

Decisao registrada: nao ha rate limiting no login de proposito. O Modulo 6 exige que a
forca bruta ACONTECA e seja DETECTADA pelos logs e tratada pelo runbook; bloquear na
aplicacao esconderia o sinal. Ver docs/runbook-forca-bruta.md.
"""

import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuracao: tudo vem do ambiente. Nenhum segredo no codigo nem na imagem.
# ---------------------------------------------------------------------------
_SECRET_KEY = os.environ.get("TASKFLOW_SECRET_KEY")
if not _SECRET_KEY:
    # Falhar na inicializacao e deliberado: um fallback silencioso reintroduziria
    # exatamente a vulnerabilidade corrigida (segredo previsivel).
    raise RuntimeError(
        "TASKFLOW_SECRET_KEY nao definida. Gere um valor aleatorio longo "
        "(ex.: python -c 'import secrets; print(secrets.token_urlsafe(48))') "
        "e exporte-o antes de iniciar a aplicacao."
    )


def _flag(nome: str, padrao: str = "0") -> bool:
    return os.environ.get(nome, padrao).lower() in {"1", "true", "yes"}


DB_PATH = Path(os.environ.get("TASKFLOW_DB_PATH", "data/taskflow.db"))
LOG_DIR = Path(os.environ.get("TASKFLOW_LOG_DIR", "logs"))
DEBUG = _flag("FLASK_DEBUG")
COOKIE_SECURE = _flag("TASKFLOW_COOKIE_SECURE")
TRUST_PROXY = _flag("TASKFLOW_TRUST_PROXY")
SEED_USERS = _flag("TASKFLOW_SEED_USERS", "1")


# ---------------------------------------------------------------------------
# Logging estruturado (Modulo 6)
# ---------------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    """Um objeto JSON por linha (NDJSON), com os campos extra do evento."""

    _CAMPOS_PADRAO = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
        "message",
        "asctime",
    }

    def format(self, record: logging.LogRecord) -> str:
        entrada = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for chave, valor in record.__dict__.items():
            if chave not in self._CAMPOS_PADRAO and chave not in entrada:
                entrada[chave] = valor
        if record.exc_info:
            entrada["exception"] = self.formatException(record.exc_info)
        return json.dumps(entrada, ensure_ascii=False, default=str)


def configurar_logging() -> logging.Logger:
    logger = logging.getLogger("taskflow")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return logger

    formatter = JsonFormatter()

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    # Arquivo para o Promtail. Se o diretorio nao for gravavel (ex.: container
    # read-only sem volume), segue so com stdout em vez de derrubar a aplicacao.
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        arquivo = RotatingFileHandler(
            LOG_DIR / "taskflow.log", maxBytes=5 * 1024 * 1024, backupCount=3
        )
        arquivo.setFormatter(formatter)
        logger.addHandler(arquivo)
    except OSError as exc:
        logger.warning(
            "log em arquivo desativado",
            extra={"event": "log_file_unavailable", "reason": str(exc)},
        )
    return logger


logger = configurar_logging()

# ---------------------------------------------------------------------------
# Aplicacao
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=_SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    MAX_CONTENT_LENGTH=64 * 1024,  # formularios pequenos; limita abuso de memoria
)


def get_db() -> sqlite3.Connection:
    db = getattr(g, "_database", None)
    if db is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):  # noqa: ARG001 - assinatura exigida pelo Flask
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            done INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()

    if SEED_USERS and db.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"] == 0:
        # Usuarios de LABORATORIO (documentados no README) para o DAST e para a
        # simulacao de forca bruta. Senhas guardadas apenas como hash com salt.
        # Em producao: TASKFLOW_SEED_USERS=0 e provisionamento proprio.
        # INSERT OR IGNORE: idempotente mesmo se dois workers inicializarem ao mesmo tempo.
        for usuario, senha in (("admin", "admin123"), ("aluno", "senha123")):  # noqa: S105
            db.execute(
                "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                (usuario, generate_password_hash(senha)),
            )
        db.commit()


with app.app_context():
    init_db()


# ---------------------------------------------------------------------------
# request_id, duracao e cabecalhos de seguranca em toda resposta
# ---------------------------------------------------------------------------
def ip_cliente() -> str:
    """IP de origem. Atras de proxy confiavel, usa o primeiro X-Forwarded-For."""
    if TRUST_PROXY:
        encaminhado = request.headers.get("X-Forwarded-For", "")
        if encaminhado:
            return encaminhado.split(",")[0].strip()
    return request.remote_addr or "desconhecido"


@app.before_request
def iniciar_requisicao():
    g.request_id = str(uuid.uuid4())
    g.inicio = time.perf_counter()


@app.after_request
def finalizar_requisicao(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Request-ID"] = g.get("request_id", "")

    duracao_ms = round((time.perf_counter() - g.get("inicio", time.perf_counter())) * 1000, 2)
    logger.info(
        "requisicao finalizada",
        extra={
            "event": "http_request",
            "request_id": g.get("request_id"),
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "duration_ms": duracao_ms,
            "ip": ip_cliente(),
            "user": session.get("username"),
        },
    )
    return response


# ---------------------------------------------------------------------------
# Rotas
# ---------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    """Liveness para o healthcheck do container. Nao toca no banco nem revela nada."""
    return {"status": "ok"}


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("tasks"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")[:150]
        password = request.form.get("password", "")

        # Consulta parametrizada: o valor nunca vira parte do comando SQL.
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            logger.info(
                "login bem-sucedido",
                extra={
                    "event": "login_attempt",
                    "result": "success",
                    "username": username,
                    "ip": ip_cliente(),
                    "request_id": g.request_id,
                },
            )
            return redirect(url_for("tasks"))

        # Mesma mensagem para usuario inexistente e senha errada (nao enumerar contas).
        error = "Usuario ou senha invalidos."
        logger.warning(
            "login falhou",
            extra={
                "event": "login_attempt",
                "result": "failure",
                "username": username,
                "ip": ip_cliente(),
                "request_id": g.request_id,
            },
        )

    # "error" passa pelo autoescape do Jinja2: nada do que o usuario digitou vira HTML.
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    logger.info(
        "logout",
        extra={"event": "logout", "username": session.get("username"), "request_id": g.request_id},
    )
    session.clear()
    return redirect(url_for("login"))


@app.route("/tasks", methods=["GET"])
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("q", "")[:100]
    db = get_db()
    if search:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], f"%{search}%"),
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)).fetchall()

    # O termo buscado e logado (ja serializado como JSON, sem risco de log injection):
    # e assim que uma varredura de payloads no campo q aparece no Grafana.
    logger.info(
        "lista de tarefas acessada",
        extra={
            "event": "tasks_list_accessed",
            "username": session.get("username"),
            "search": search or None,
            "count": len(rows),
            "request_id": g.request_id,
        },
    )
    return render_template("tasks.html", tasks=rows, username=session["username"], search=search)


@app.route("/tasks/new", methods=["GET", "POST"])
def new_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()[:200]
        description = request.form.get("description", "").strip()[:2000]
        if not title:
            return render_template("new_task.html", error="O titulo e obrigatorio."), 400
        db = get_db()
        cursor = db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
            (session["user_id"], title, description),
        )
        db.commit()
        logger.info(
            "tarefa criada",
            extra={
                "event": "task_created",
                "username": session.get("username"),
                "task_id": cursor.lastrowid,
                "title_length": len(title),
                "request_id": g.request_id,
            },
        )
        return redirect(url_for("tasks"))

    return render_template("new_task.html", error=None)


if __name__ == "__main__":
    # Servidor de desenvolvimento, so para uso local: escuta apenas em localhost e
    # com debug desligado por padrao. Em container o processo e o gunicorn (Dockerfile).
    app.run(host="127.0.0.1", port=5000, debug=DEBUG)
