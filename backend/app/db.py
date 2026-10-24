"""Persistence layer.

The schema below is written to be Postgres-compatible (plain column types,
no SQLite-only features) because PostgreSQL is the stack the resume
claims and is what the schema, and the committed Grafana dashboard JSON,
are designed against. PostgreSQL itself is not installed as a running
service on this build machine (see README "Honest framing"); the same
schema is exercised for real against local SQLite so every test and API
call in this repo actually runs against a real database engine, just not
Postgres. If POSTGRES_URL is set and reachable, the app and tests use it
instead and exercise the real thing.

Stand-up command for a real local Postgres, documented rather than run
unattended on a shared machine (BUILDER.md 3z/3a):

    docker run --name mwaa-postgres -e POSTGRES_PASSWORD=mwaa -e POSTGRES_DB=mwaa \
        -p 5432:5432 -d postgres:16
    export POSTGRES_URL=postgresql+psycopg2://postgres:mwaa@localhost:5432/mwaa
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class RuleRow(Base):
    __tablename__ = "rules"
    rule_id = Column(String(64), primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    window_aware = Column(Integer, nullable=False)  # 0/1, portable across engines


class CalendarWindowRow(Base):
    __tablename__ = "calendar_windows"
    window_id = Column(String(64), primary_key=True)
    attraction = Column(String(64), nullable=False)
    host = Column(String(64), nullable=False)
    start = Column(DateTime, nullable=False)
    end = Column(DateTime, nullable=False)
    window_type = Column(String(32), nullable=False)
    ticket = Column(String(64), nullable=False)
    description = Column(Text, nullable=False)


class AlertRow(Base):
    __tablename__ = "alerts"
    alert_id = Column(String(200), primary_key=True)
    rule_id = Column(String(64), nullable=False)
    rule_name = Column(String(200), nullable=False)
    host = Column(String(64), nullable=False)
    attraction = Column(String(64), nullable=False)
    ts = Column(DateTime, nullable=False)
    triggering_lines = Column(Text, nullable=False)  # JSON-encoded list[str]
    explanation = Column(Text, nullable=False)
    window_state = Column(String(32), nullable=False)
    technique_id = Column(String(16), nullable=False)
    technique_name = Column(String(200), nullable=False)
    # Process-ancestry attribution; null for alerts with no causing process
    # (MISSED_PATCH_WINDOW). See app/correlation.py.
    pid = Column(Integer, nullable=True)
    ppid = Column(Integer, nullable=True)


def database_url() -> str:
    pg = os.environ.get("POSTGRES_URL")
    if pg:
        return pg
    sqlite_path = os.environ.get("SQLITE_PATH", "./data/app.db")
    os.makedirs(os.path.dirname(sqlite_path) or ".", exist_ok=True)
    return f"sqlite:///{sqlite_path}"


def make_engine(url: str | None = None):
    url = url or database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


def make_session_factory(engine):
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def postgres_reachable(url: str) -> bool:
    """Best-effort connectivity probe used by tests to skip cleanly."""
    try:
        engine = create_engine(url)
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True
    except Exception:
        return False


def alert_to_row(alert) -> AlertRow:
    from .attack import mapping_for

    mapping = mapping_for(alert.rule_id)
    return AlertRow(
        alert_id=alert.alert_id,
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        host=alert.host,
        attraction=alert.attraction,
        ts=alert.ts,
        triggering_lines=json.dumps(list(alert.triggering_lines)),
        explanation=alert.explanation,
        window_state=alert.window_state,
        technique_id=mapping.technique_id,
        technique_name=mapping.technique_name,
        pid=alert.pid,
        ppid=alert.ppid,
    )


def row_to_alert(row: AlertRow):
    """The reverse of alert_to_row: reconstructs the dataclass Alert
    object so app/correlation.py (which only knows about Alert, not the
    ORM) can group rows read back out of the database."""
    from .models import Alert

    return Alert(
        alert_id=row.alert_id,
        rule_id=row.rule_id,
        rule_name=row.rule_name,
        host=row.host,
        attraction=row.attraction,
        ts=row.ts,
        triggering_lines=tuple(json.loads(row.triggering_lines)),
        explanation=row.explanation,
        window_state=row.window_state,
        pid=row.pid,
        ppid=row.ppid,
    )


def row_to_dict(row: AlertRow) -> dict:
    return {
        "alert_id": row.alert_id,
        "rule_id": row.rule_id,
        "rule_name": row.rule_name,
        "host": row.host,
        "attraction": row.attraction,
        "ts": row.ts.isoformat(),
        "triggering_lines": json.loads(row.triggering_lines),
        "explanation": row.explanation,
        "window_state": row.window_state,
        "technique_id": row.technique_id,
        "technique_name": row.technique_name,
        "pid": row.pid,
        "ppid": row.ppid,
    }


def window_to_dict(row: CalendarWindowRow) -> dict:
    return {
        "window_id": row.window_id,
        "attraction": row.attraction,
        "host": row.host,
        "start": row.start.isoformat(),
        "end": row.end.isoformat(),
        "window_type": row.window_type,
        "ticket": row.ticket,
        "description": row.description,
    }


def rule_to_dict(row: RuleRow) -> dict:
    return {
        "rule_id": row.rule_id,
        "name": row.name,
        "description": row.description,
        "window_aware": bool(row.window_aware),
    }
