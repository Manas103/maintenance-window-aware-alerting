"""Claim: nine named rules scored against the attraction's published
maintenance calendar, covering the five named categories plus four more."""
from app.generators import ATTRACTIONS, build_calendar
from app.rules import RULES


def test_exactly_nine_named_rules():
    assert len(RULES) == 9
    ids = {r.rule_id for r in RULES}
    assert len(ids) == 9, "rule ids must be unique"
    for r in RULES:
        assert r.name
        assert r.description


def test_required_five_rule_categories_present():
    names = " ".join(r.name.lower() for r in RULES)
    required_substrings = [
        "new executable",
        "removable media",
        "engineering laptop",
        "missed patch window",
        "clock drift",
    ]
    for s in required_substrings:
        assert s in names, f"required rule category missing: {s}"


def test_calendar_scores_every_attraction_and_control_host():
    calendar = build_calendar(num_weeks=4)
    assert len(calendar) > 0
    seen_attractions = {w.attraction for w in calendar}
    assert seen_attractions == set(ATTRACTIONS.keys())
    for attraction, cfg in ATTRACTIONS.items():
        hosts_with_patch_windows = {
            w.host for w in calendar if w.attraction == attraction and w.window_type == "patch"
        }
        assert hosts_with_patch_windows == set(cfg["control"])
