"""Claim: each rule mapped to a MITRE ATT&CK technique."""
from app.attack import ATTACK_MAPPING
from app.rules import RULES


def test_every_rule_has_exactly_one_mapping():
    assert set(ATTACK_MAPPING) == {r.rule_id for r in RULES}
    assert len(ATTACK_MAPPING) == 9


def test_every_mapping_has_a_real_looking_technique_id():
    for rule_id, mapping in ATTACK_MAPPING.items():
        assert mapping.technique_id.startswith("T")
        assert mapping.technique_name
        assert mapping.tactic


def test_imperfect_mappings_are_named_and_explained():
    imperfect = {rid for rid, m in ATTACK_MAPPING.items() if m.imperfect}
    assert imperfect == {"MISSED_PATCH_WINDOW", "CLOCK_DRIFT"}
    for rid in imperfect:
        assert ATTACK_MAPPING[rid].note
