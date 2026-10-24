"""Prints the correlation-stage measurement: raw alert count before
grouping, incident count after, the analyst-facing reduction percentage,
a sample incident, and the primary/reference correlation oracle diff.
Run with:
    python tools/dump_correlation_output.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.correlation import PrimaryCorrelationEngine, analyst_facing_reduction  # noqa: E402
from app.correlation_fixtures import CORRELATION_AS_OF, build_correlation_corpus  # noqa: E402
from app.engine import PrimaryEngine  # noqa: E402
from app.generators import known_good_hashes  # noqa: E402
from app.reference_correlation import ReferenceCorrelationEngine  # noqa: E402


def main():
    events, calendar, chained_incidents, standalone = build_correlation_corpus()
    hashes = known_good_hashes()
    alerts = PrimaryEngine().evaluate(events, calendar, hashes, as_of=CORRELATION_AS_OF)

    print(f"== raw alerts ({len(chained_incidents)} chained scenarios x 8 + "
          f"{len(standalone)} standalone) ==")
    print(f"total alerts: {len(alerts)}")
    print()

    primary_incidents = PrimaryCorrelationEngine().group(alerts)
    reference_incidents = ReferenceCorrelationEngine().group(alerts)

    print("== correlation oracle diff (primary BFS vs. reference union-find) ==")
    p_keys = {inc.content_key() for inc in primary_incidents}
    r_keys = {inc.content_key() for inc in reference_incidents}
    only_primary = p_keys - r_keys
    only_reference = r_keys - p_keys
    print(f"primary incidents:   {len(primary_incidents)}")
    print(f"reference incidents: {len(reference_incidents)}")
    print(f"only in primary:   {len(only_primary)}")
    print(f"only in reference: {len(only_reference)}")
    print(f"EXACT AGREEMENT: {only_primary == set() and only_reference == set()}")
    print()

    multi = [inc for inc in primary_incidents if inc.alert_count() > 1]
    single = [inc for inc in primary_incidents if inc.alert_count() == 1]
    print(f"== grouping result ==")
    print(f"multi-alert incidents (true chains folded):   {len(multi)}")
    print(f"single-alert incidents (correctly left alone): {len(single)}")
    print()

    result = analyst_facing_reduction(alerts)
    print("== 76% fewer analyst-facing items claim ==")
    print(f"alerts before correlation:   {result['alerts_before']}")
    print(f"incidents after correlation: {result['incidents_after']}")
    print(f"measured reduction:          {result['reduction_pct']}% (design target: 76%)")
    print()

    sample = multi[0]
    print("== sample incident ==")
    print(f"incident_id:   {sample.incident_id}")
    print(f"alert_count:   {sample.alert_count()}")
    print(f"rule_ids:      {sample.rule_ids}")
    print(f"technique_ids: {sample.technique_ids}")
    print(f"hosts:         {sample.hosts}")
    print(f"fidelity_score: {sample.fidelity_score} / 100")
    print(f"span:          {sample.start_ts} -> {sample.end_ts}")


if __name__ == "__main__":
    main()
