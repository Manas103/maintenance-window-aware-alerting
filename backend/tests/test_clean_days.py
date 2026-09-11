"""Claim: 0 false alerts across 40 clean operating days."""
from app.engine import PrimaryEngine
from app.generators import build_clean_corpus, known_good_hashes


def test_zero_false_alerts_across_forty_clean_days():
    events, calendar = build_clean_corpus(num_days=40)
    assert len(events) > 0

    alerts = PrimaryEngine().evaluate(events, calendar, known_good_hashes())

    assert alerts == [], (
        f"expected 0 false alerts over 40 clean operating days, got "
        f"{len(alerts)}: {[(a.rule_id, a.host, a.ts) for a in alerts]}"
    )
