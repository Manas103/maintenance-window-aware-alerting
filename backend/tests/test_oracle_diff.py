"""Claim: exact agreement with an independent reference detector.

Diffs the primary (pandas-indexed) engine against the reference
(plain-loop) engine over the full seeded corpus (14 clean baseline days
plus 40 seeded incidents) and separately over 10 clean operating days, and
requires the two alert sets to be identical.
"""
from app.engine import PrimaryEngine
from app.generators import build_clean_corpus, build_seeded_corpus, known_good_hashes
from app.reference_engine import ReferenceEngine


def _diff(primary_alerts, reference_alerts):
    p_keys = {a.key() for a in primary_alerts}
    r_keys = {a.key() for a in reference_alerts}
    only_primary = p_keys - r_keys
    only_reference = r_keys - p_keys
    return only_primary, only_reference


def test_oracle_agrees_exactly_on_seeded_corpus():
    events, calendar, scenarios, as_of = build_seeded_corpus()
    hashes = known_good_hashes()

    primary_alerts = PrimaryEngine().evaluate(events, calendar, hashes, as_of=as_of)
    reference_alerts = ReferenceEngine().evaluate(events, calendar, hashes, as_of=as_of)

    only_primary, only_reference = _diff(primary_alerts, reference_alerts)

    assert only_primary == set(), f"primary engine alerted but reference did not: {only_primary}"
    assert only_reference == set(), f"reference engine alerted but primary did not: {only_reference}"
    assert len(primary_alerts) == len(reference_alerts) == 40
    assert len(scenarios) == 40


def test_oracle_agrees_exactly_on_clean_days():
    events, calendar = build_clean_corpus(num_days=10)
    hashes = known_good_hashes()

    primary_alerts = PrimaryEngine().evaluate(events, calendar, hashes)
    reference_alerts = ReferenceEngine().evaluate(events, calendar, hashes)

    only_primary, only_reference = _diff(primary_alerts, reference_alerts)
    assert only_primary == set()
    assert only_reference == set()
    assert primary_alerts == [] and reference_alerts == []
