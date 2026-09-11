"""Prints the exact diff between the primary and reference detection
engines over the seeded corpus and the clean-days corpus. Run with:
    python tools/dump_oracle_diff.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine import PrimaryEngine  # noqa: E402
from app.generators import build_clean_corpus, build_seeded_corpus, known_good_hashes  # noqa: E402
from app.reference_engine import ReferenceEngine  # noqa: E402


def diff_report(label, events, calendar, hashes, as_of=None):
    primary = PrimaryEngine().evaluate(events, calendar, hashes, as_of=as_of)
    reference = ReferenceEngine().evaluate(events, calendar, hashes, as_of=as_of)
    p_keys = {a.key() for a in primary}
    r_keys = {a.key() for a in reference}
    only_primary = p_keys - r_keys
    only_reference = r_keys - p_keys
    print(f"== {label} ==")
    print(f"primary alerts:   {len(primary)}")
    print(f"reference alerts: {len(reference)}")
    print(f"only in primary:   {len(only_primary)}")
    print(f"only in reference: {len(only_reference)}")
    print(f"EXACT AGREEMENT: {only_primary == set() and only_reference == set()}")
    print()
    return only_primary == set() and only_reference == set()


def main():
    hashes = known_good_hashes()

    events, calendar, scenarios, as_of = build_seeded_corpus()
    ok1 = diff_report(f"seeded corpus ({len(scenarios)} scenarios + 14 clean baseline days)",
                       events, calendar, hashes, as_of=as_of)

    clean_events, clean_calendar = build_clean_corpus(num_days=40)
    ok2 = diff_report("40 clean operating days", clean_events, clean_calendar, hashes)

    print(f"ALL CORPORA AGREE EXACTLY: {ok1 and ok2}")


if __name__ == "__main__":
    main()
