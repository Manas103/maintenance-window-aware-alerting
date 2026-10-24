"""Populate the database the API serves from.

Runs the primary engine over the seeded-incident corpus (14 clean baseline
days plus the 40 seeded scenarios) so the API and dashboard have a
realistic, non-trivial alert feed to show, and loads the rule table and
maintenance calendar alongside it. Also runs it over the separate
correlation corpus (correlation_fixtures.py: 15 process-ancestry-chained
incidents plus 18 standalone alerts) and appends those alerts too, so
GET /incidents has something to actually group; the two corpora's alerts
coexist in the same table and are distinguished only by whether `pid` is
set, exactly like app/correlation.py already expects.
"""
from __future__ import annotations

from .correlation_fixtures import CORRELATION_AS_OF, build_correlation_corpus
from .db import (
    AlertRow,
    CalendarWindowRow,
    RuleRow,
    alert_to_row,
    make_engine,
    make_session_factory,
)
from .engine import PrimaryEngine
from .generators import build_seeded_corpus, known_good_hashes
from .rules import RULES


def seed(session_factory) -> int:
    hashes = known_good_hashes()

    events, calendar, _scenarios, as_of = build_seeded_corpus()
    alerts = PrimaryEngine().evaluate(events, calendar, hashes, as_of=as_of)

    corr_events, corr_calendar, _chained, _standalone = build_correlation_corpus()
    corr_alerts = PrimaryEngine().evaluate(corr_events, corr_calendar, hashes, as_of=CORRELATION_AS_OF)

    session = session_factory()
    try:
        session.query(AlertRow).delete()
        session.query(CalendarWindowRow).delete()
        session.query(RuleRow).delete()

        for r in RULES:
            session.add(RuleRow(
                rule_id=r.rule_id, name=r.name, description=r.description,
                window_aware=1 if r.window_aware else 0,
            ))
        for w in calendar:
            session.add(CalendarWindowRow(
                window_id=w.window_id, attraction=w.attraction, host=w.host,
                start=w.start, end=w.end, window_type=w.window_type,
                ticket=w.ticket, description=w.description,
            ))
        for a in alerts:
            session.add(alert_to_row(a))
        for a in corr_alerts:
            session.add(alert_to_row(a))
        session.commit()
        return len(alerts) + len(corr_alerts)
    finally:
        session.close()


if __name__ == "__main__":
    engine = make_engine()
    factory = make_session_factory(engine)
    n = seed(factory)
    print(f"seeded {n} alerts into {engine.url}")
