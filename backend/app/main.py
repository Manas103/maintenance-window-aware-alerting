"""FastAPI service: serves the alert feed, rule table and maintenance
calendar to the React dashboard, reading from the database configured by
db.database_url() (PostgreSQL if POSTGRES_URL is set and reachable,
otherwise local SQLite; see db.py for why)."""
from __future__ import annotations

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from .db import (
    AlertRow,
    CalendarWindowRow,
    RuleRow,
    make_engine,
    make_session_factory,
    row_to_dict,
    rule_to_dict,
    window_to_dict,
)

app = FastAPI(title="Maintenance-Window-Aware Alerting API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_engine = make_engine()
_SessionFactory = make_session_factory(_engine)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/rules")
def list_rules():
    session = _SessionFactory()
    try:
        return [rule_to_dict(r) for r in session.query(RuleRow).order_by(RuleRow.rule_id)]
    finally:
        session.close()


@app.get("/calendar")
def list_calendar(attraction: str | None = None):
    session = _SessionFactory()
    try:
        q = session.query(CalendarWindowRow)
        if attraction:
            q = q.filter(CalendarWindowRow.attraction == attraction)
        return [window_to_dict(w) for w in q.order_by(CalendarWindowRow.start)]
    finally:
        session.close()


@app.get("/alerts")
def list_alerts(
    rule_id: str | None = None,
    attraction: str | None = None,
    limit: int = Query(500, le=5000),
):
    session = _SessionFactory()
    try:
        q = session.query(AlertRow)
        if rule_id:
            q = q.filter(AlertRow.rule_id == rule_id)
        if attraction:
            q = q.filter(AlertRow.attraction == attraction)
        rows = q.order_by(AlertRow.ts.desc()).limit(limit).all()
        return [row_to_dict(r) for r in rows]
    finally:
        session.close()
