"""Claim: 40 of 40 seeded events alerted naming the rule and its
triggering log lines."""
from app.engine import PrimaryEngine
from app.generators import build_seeded_corpus, known_good_hashes
from app.rules import RULES_BY_ID


def test_forty_of_forty_seeded_events_alert_naming_rule_and_lines():
    events, calendar, scenarios, as_of = build_seeded_corpus()
    assert len(scenarios) == 40

    alerts = PrimaryEngine().evaluate(events, calendar, known_good_hashes(), as_of=as_of)

    matched = 0
    unmatched = []
    for sc in scenarios:
        expected_lines = {e.raw for e in sc["events"]} if sc["events"] else None
        hit = None
        for a in alerts:
            if a.rule_id != sc["rule_id"] or a.host != sc["host"]:
                continue
            if abs((a.ts - sc["ts"]).total_seconds()) > 1:
                continue
            if expected_lines is not None and not expected_lines.issubset(set(a.triggering_lines)):
                continue
            hit = a
            break
        if hit is None:
            unmatched.append(sc)
            continue
        # Every alert must name its rule and quote at least one triggering line.
        assert hit.rule_name == RULES_BY_ID[sc["rule_id"]].name
        assert len(hit.triggering_lines) >= 1
        matched += 1

    assert unmatched == []
    assert matched == 40

    # And nothing extra fired: exactly one alert per scenario, no noise
    # from the 14-day clean baseline that surrounds them.
    assert len(alerts) == 40
