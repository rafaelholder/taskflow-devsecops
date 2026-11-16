# Dockerfile endurecido (Modulo 2). Cada bloco cita a FALHA da linha de base que corrige.
#
# FALHA 1 (python:latest)  -> base minima com tag E digest fixados: build reprodutivel,
#                              nenhuma atualizacao silenciosa da imagem base.
# FALHA 2 (root)           -> usuario de sistema dedicado, UID fixo, sem shell nem home.
# FALHA 3 (sem integridade)-> pip install --require-hashes: cada pacote (inclusive transitivo)
#                              tem o hash conferido contra requirements.txt (gerado por
#                              uv pip compile --generate-hashes). Pacote adulterado = build falha.
# FALHA 4 (ENV com segredo)-> nenhum ENV/ARG com segredo; TASKFLOW_SECRET_KEY entra em runtime.
# FALHA 5/6 (dev server,   -> gunicorn como servidor WSGI; FLASK_DEBUG nao existe na imagem
#            debug, root)     (padrao da aplicacao e desligado); processo roda como taskflow.
# Extra: multi-stage (sem pip/cache na imagem final), HEALTHCHECK, PYTHONDONTWRITEBYTECODE.

# ---- estagio 1: resolve dependencias ---------------------------------------
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /build
COPY requirements.txt .
RUN pip install --require-hashes --no-deps --prefix=/install -r requirements.txt

# ---- estagio 2: imagem final ------------------------------------------------
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TASKFLOW_DB_PATH=/app/data/taskflow.db \
    TASKFLOW_LOG_DIR=/app/logs

COPY --from=build /install /usr/local

RUN groupadd --system --gid 10001 taskflow \
    && useradd --system --uid 10001 --gid taskflow --no-create-home --shell /usr/sbin/nologin taskflow \
    && mkdir -p /app/data /app/logs \
    && chown -R taskflow:taskflow /app

WORKDIR /app
COPY --chown=taskflow:taskflow app.py ./
COPY --chown=taskflow:taskflow templates/ templates/

USER taskflow

EXPOSE 5000

# Liveness sem tocar no banco; usa a stdlib para nao precisar de curl na imagem.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3)"]

# --preload: o modulo (e o init_db) carrega uma vez no master, antes dos workers.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--preload", "--access-logfile", "-", "app:app"]
