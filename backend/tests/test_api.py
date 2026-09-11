"""API tests against local SQLite (default) and, if POSTGRES_URL is set
and reachable, against real PostgreSQL too, skipping cleanly otherwise
per BUILDER.md section 3 precedent."""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import close_all_sessions

from app.db import make_engine, make_session_factory, postgres_reachable
from app.seed_db import seed


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.setenv("SQLITE_PATH", str(db_path))

    import importlib

    import app.main as main_module

    importlib.reload(main_module)
    seed(main_module._SessionFactory)
    yield TestClient(main_module.app)
    close_all_sessions()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_rules_endpoint_returns_nine(client):
    r = client.get("/rules")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 9


def test_calendar_endpoint_nonempty(client):
    r = client.get("/calendar")
    assert r.status_code == 200
    assert len(r.json()) > 0


def test_alerts_endpoint_returns_forty(client):
    r = client.get("/alerts", params={"limit": 100})
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 40
    for a in body:
        assert a["rule_id"]
        assert a["triggering_lines"]


@pytest.mark.skipif(
    not postgres_reachable(os.environ.get("POSTGRES_URL", "")),
    reason="PostgreSQL not running as a service on this machine (POSTGRES_URL unset or unreachable)",
)
def test_against_real_postgres():
    engine = make_engine(os.environ["POSTGRES_URL"])
    factory = make_session_factory(engine)
    n = seed(factory)
    assert n == 40
