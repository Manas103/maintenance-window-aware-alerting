"""Claim: exact agreement with an independent reference engine, extended to
the correlation stage. Diffs PrimaryCorrelationEngine against
ReferenceCorrelationEngine (BFS vs. union-find, no shared helper code)
over the full correlation corpus."""
from app.correlation import PrimaryCorrelationEngine
from app.correlation_fixtures import CORRELATION_AS_OF, build_correlation_corpus
from app.engine import PrimaryEngine
from app.generators import known_good_hashes
from app.reference_correlation import ReferenceCorrelationEngine


def test_correlation_oracle_agrees_exactly():
    events, calendar, chained_incidents, standalone = build_correlation_corpus()
    hashes = known_good_hashes()
    alerts = PrimaryEngine().evaluate(events, calendar, hashes, as_of=CORRELATION_AS_OF)

    primary_incidents = PrimaryCorrelationEngine().group(alerts)
    reference_incidents = ReferenceCorrelationEngine().group(alerts)

    primary_keys = {inc.content_key() for inc in primary_incidents}
    reference_keys = {inc.content_key() for inc in reference_incidents}

    only_primary = primary_keys - reference_keys
    only_reference = reference_keys - primary_keys

    assert only_primary == set(), f"primary grouped but reference did not: {only_primary}"
    assert only_reference == set(), f"reference grouped but primary did not: {only_reference}"
    assert len(primary_incidents) == len(reference_incidents)
