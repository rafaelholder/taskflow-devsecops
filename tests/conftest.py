"""Ambiente de teste isolado: segredo de teste, banco e logs em pasta temporaria."""

import os
import re
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="taskflow-test-"))
os.environ.setdefault("TASKFLOW_SECRET_KEY", "teste-apenas-nao-e-segredo-real")
os.environ["TASKFLOW_DB_PATH"] = str(_TMP / "taskflow.db")
os.environ["TASKFLOW_LOG_DIR"] = str(_TMP / "logs")

import app as taskflow  # noqa: E402 - precisa do ambiente acima antes do import


@pytest.fixture()
def client():
    taskflow.app.config["TESTING"] = True
    with taskflow.app.test_client() as c:
        yield c


def token_de(html: str) -> str:
    achado = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert achado, "formulario sem token CSRF"
    return achado.group(1)


@pytest.fixture()
def login(client):
    def _login(usuario="admin", senha="admin123"):  # noqa: S107 - credencial de laboratorio
        token = token_de(client.get("/login").get_data(as_text=True))
        return client.post(
            "/login", data={"username": usuario, "password": senha, "csrf_token": token}
        )

    return _login


@pytest.fixture()
def log_file():
    return _TMP / "logs" / "taskflow.log"
