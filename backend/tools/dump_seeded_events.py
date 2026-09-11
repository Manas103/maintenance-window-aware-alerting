"""Prints the 40/40 seeded-event result: every scenario, the rule that
fired, and the exact triggering log line(s), plus the false-alert count on
the 40 clean operating days. Run with:
    python tools/dump_seeded_events.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine import PrimaryEngine  # noqa: E402
from app.generators import build_clean_corpus, build_seeded_corpus, known_good_hashes  # noqa: E402


def main():
    events, calendar, scenarios, as_of = build_seeded_corpus()
    hashes = known_good_hashes()
    alerts = PrimaryEngine().evaluate(events, calendar, hashes, as_of=as_of)

    print(f"Seeded scenarios: {len(scenarios)}")
    print(f"Alerts fired: {len(alerts)}")
    print()
    matched = 0
    for i, sc in enumerate(scenarios, 1):
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
        status = "ALERTED" if hit else "MISSED"
        if hit:
            matched += 1
        print(f"[{i:02d}/40] {sc['rule_id']:<32} host={sc['host']:<20} -> {status}")
        if hit:
            print(f"        rule: {hit.rule_name}")
            for line in hit.triggering_lines:
                print(f"        line: {line}")
        print()

    print(f"SUMMARY: {matched} of {len(scenarios)} seeded events alerted naming the rule "
          "and its triggering log line(s)")
    print()

    clean_events, clean_calendar = build_clean_corpus(num_days=40)
    clean_alerts = PrimaryEngine().evaluate(clean_events, clean_calendar, hashes)
    print(f"Clean operating days evaluated: 40")
    print(f"False alerts on clean days: {len(clean_alerts)}")


if __name__ == "__main__":
    main()
