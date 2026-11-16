"""The merge gate: every rule must carry a version-controlled Sigma-style
definition, a documented false-positive case, and a response runbook.

This is deliberately a separate module from rules.py and attack.py (the
rule's identity and ATT&CK mapping) so that the gate is checking the
*paperwork* a rule is required to carry, not re-deriving the rule's own
logic. check_rules() is called by both the CI workflow
(.github/workflows/rule-gate.yml) and tests/test_rule_gate.py; the two
call sites exercise the same function against two different directories
(the real rules/sigma/ for a green run, and mutated fixture copies for
the red-path tests), so the gate's behavior is proven, not just its
existence.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from .rules import RULES

REQUIRED_RUNBOOK_SECTIONS = ("## Triage", "## Containment", "## Remediation", "## Escalation")
MIN_FALSEPOSITIVE_CHARS = 40
MIN_RUNBOOK_CHARS = 200


@dataclass
class GateViolation:
    rule_id: str
    reason: str

    def __str__(self) -> str:
        return f"{self.rule_id}: {self.reason}"


def _load_sigma_rules(sigma_dir: Path) -> dict[str, dict]:
    rules = {}
    for path in sorted(sigma_dir.glob("*.yml")):
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        rules[path.stem] = doc
    return rules


def check_rules(sigma_dir: Path, runbooks_dir: Path, expected_rule_ids=None) -> list[GateViolation]:
    """Return every gate violation found. Empty list means every rule may
    merge. expected_rule_ids defaults to the live rule table (rules.py) so
    a rule added there without a matching Sigma file is itself a
    violation, not a silent gap."""
    expected_rule_ids = expected_rule_ids if expected_rule_ids is not None else {r.rule_id for r in RULES}
    violations: list[GateViolation] = []

    sigma_rules = _load_sigma_rules(sigma_dir)

    for rule_id in sorted(expected_rule_ids):
        if rule_id not in sigma_rules:
            violations.append(GateViolation(rule_id, "no version-controlled Sigma rule file found"))
            continue

        doc = sigma_rules[rule_id]

        if doc.get("id") != rule_id:
            violations.append(GateViolation(
                rule_id, f"Sigma file id field ({doc.get('id')!r}) does not match its filename"
            ))

        fps = doc.get("falsepositives")
        if not fps or not isinstance(fps, list):
            violations.append(GateViolation(rule_id, "no documented false-positive case (falsepositives list is empty or missing)"))
        else:
            real_cases = [fp for fp in fps if isinstance(fp, str) and len(fp.strip()) >= MIN_FALSEPOSITIVE_CHARS]
            if not real_cases:
                violations.append(GateViolation(
                    rule_id,
                    "falsepositives entry present but too short to be a documented case "
                    f"(needs >= {MIN_FALSEPOSITIVE_CHARS} characters, not a placeholder like 'Unknown')",
                ))

        runbook_field = doc.get("runbook")
        if not runbook_field:
            violations.append(GateViolation(rule_id, "no runbook field in the Sigma file"))
            continue

        runbook_path = runbooks_dir.parent / runbook_field
        if not runbook_path.is_file():
            violations.append(GateViolation(rule_id, f"runbook file not found: {runbook_field}"))
            continue

        text = runbook_path.read_text(encoding="utf-8")
        if len(text) < MIN_RUNBOOK_CHARS:
            violations.append(GateViolation(rule_id, "runbook file exists but is too short to be a real response runbook"))
        missing_sections = [s for s in REQUIRED_RUNBOOK_SECTIONS if s not in text]
        if missing_sections:
            violations.append(GateViolation(
                rule_id, f"runbook is missing required section(s): {', '.join(missing_sections)}"
            ))

    for rule_id in sorted(set(sigma_rules) - expected_rule_ids):
        violations.append(GateViolation(rule_id, "Sigma rule file exists for a rule_id not in the live rule table (rules.py)"))

    return violations


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    repo_root = Path(__file__).resolve().parent.parent
    sigma_dir = Path(argv[0]) if len(argv) > 0 else repo_root / "rules" / "sigma"
    runbooks_dir = Path(argv[1]) if len(argv) > 1 else repo_root / "runbooks"

    violations = check_rules(sigma_dir, runbooks_dir)
    if violations:
        print(f"RULE MERGE GATE: BLOCKED ({len(violations)} violation(s))")
        for v in violations:
            print(f"  - {v}")
        return 1

    print("RULE MERGE GATE: PASS (every rule carries a Sigma definition, a documented false-positive case, and a response runbook)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
