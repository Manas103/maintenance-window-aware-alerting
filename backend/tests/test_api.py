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


def test_alerts_endpoint_returns_forty_detection_plus_correlation_alerts(client):
    # 40 from the original detection corpus (generators.build_seeded_corpus,
    # unchanged) plus 138 from the separate correlation corpus (15 chained
    # incidents x 8 + 18 standalone; see correlation_fixtures.py), both
    # seeded into the same table by seed_db.seed.
    r = client.get("/alerts", params={"limit": 500})
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 40 + 138
    for a in body:
        assert a["rule_id"]
        assert a["triggering_lines"]
        assert a["technique_id"]


def test_incidents_endpoint_matches_correlation_measurement(client):
    r = client.get("/incidents")
    assert r.status_code == 200
    body = r.json()
    incidents = body["incidents"]
    multi = [i for i in incidents if i["alert_count"] > 1]
    single = [i for i in incidents if i["alert_count"] == 1]
    # The 40 original detection-corpus alerts carry no pid, so each is its
    # own singleton incident alongside the correlation corpus's 18
    # deliberately standalone alerts: 40 + 18 = 58.
    assert len(multi) == 15
    assert len(single) == 40 + 18
    assert body["reduction"]["alerts_before"] == 40 + 138
    assert body["reduction"]["incidents_after"] == 15 + 40 + 18


@pytest.mark.skipif(
    not postgres_reachable(os.environ.get("POSTGRES_URL", "")),
    reason="PostgreSQL not running as a service on this machine (POSTGRES_URL unset or unreachable)",
)
def test_against_real_postgres():
    engine = make_engine(os.environ["POSTGRES_URL"])
    factory = make_session_factory(engine)
    n = seed(factory)
    assert n == 40 + 138
