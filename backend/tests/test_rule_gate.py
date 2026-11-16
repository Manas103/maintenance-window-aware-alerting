"""Proves the merge gate actually gates, not just that it exists.

Each red-path test copies the real rules/sigma + runbooks trees into a
tmp_path, mutates exactly one file to remove one required thing, and
asserts the gate names that exact rule_id and reason. The green-path test
runs the same function against the real, unmutated trees.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from app.rule_gate import check_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_SIGMA_DIR = REPO_ROOT / "rules" / "sigma"
REAL_RUNBOOKS_DIR = REPO_ROOT / "runbooks"


def _copy_trees(tmp_path: Path):
    sigma_dir = tmp_path / "sigma"
    runbooks_dir = tmp_path / "runbooks"
    shutil.copytree(REAL_SIGMA_DIR, sigma_dir)
    shutil.copytree(REAL_RUNBOOKS_DIR, runbooks_dir)
    return sigma_dir, runbooks_dir


def test_real_rules_pass_the_gate_clean():
    violations = check_rules(REAL_SIGMA_DIR, REAL_RUNBOOKS_DIR)
    assert violations == []


def test_gate_blocks_a_rule_missing_a_sigma_file(tmp_path):
    sigma_dir, runbooks_dir = _copy_trees(tmp_path)
    (sigma_dir / "CLOCK_DRIFT.yml").unlink()

    violations = check_rules(sigma_dir, runbooks_dir)

    assert len(violations) == 1
    assert violations[0].rule_id == "CLOCK_DRIFT"
    assert "no version-controlled Sigma rule file" in violations[0].reason


def test_gate_blocks_a_rule_missing_a_documented_false_positive(tmp_path):
    sigma_dir, runbooks_dir = _copy_trees(tmp_path)
    path = sigma_dir / "ISOLATED_HOST_OUTBOUND.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["falsepositives"] = ["Unknown"]
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    violations = check_rules(sigma_dir, runbooks_dir)

    assert len(violations) == 1
    assert violations[0].rule_id == "ISOLATED_HOST_OUTBOUND"
    assert "too short to be a documented case" in violations[0].reason


def test_gate_blocks_a_rule_missing_falsepositives_entirely(tmp_path):
    sigma_dir, runbooks_dir = _copy_trees(tmp_path)
    path = sigma_dir / "REPEATED_FAILED_AUTH_HMI.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    del doc["falsepositives"]
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")

    violations = check_rules(sigma_dir, runbooks_dir)

    assert len(violations) == 1
    assert violations[0].rule_id == "REPEATED_FAILED_AUTH_HMI"
    assert "no documented false-positive case" in violations[0].reason


def test_gate_blocks_a_rule_whose_runbook_file_is_missing(tmp_path):
    sigma_dir, runbooks_dir = _copy_trees(tmp_path)
    (runbooks_dir / "UNEXPECTED_SERVICE_LOGON.md").unlink()

    violations = check_rules(sigma_dir, runbooks_dir)

    assert len(violations) == 1
    assert violations[0].rule_id == "UNEXPECTED_SERVICE_LOGON"
    assert "runbook file not found" in violations[0].reason


def test_gate_blocks_a_rule_whose_runbook_is_missing_a_required_section(tmp_path):
    sigma_dir, runbooks_dir = _copy_trees(tmp_path)
    path = runbooks_dir / "NEW_EXEC_CONTROL_HOST.md"
    text = path.read_text(encoding="utf-8")
    text = text.replace("## Escalation", "## Notes")
    path.write_text(text, encoding="utf-8")

    violations = check_rules(sigma_dir, runbooks_dir)

    assert len(violations) == 1
    assert violations[0].rule_id == "NEW_EXEC_CONTROL_HOST"
    assert "missing required section" in violations[0].reason
    assert "Escalation" in violations[0].reason


def test_gate_blocks_a_sigma_file_for_a_rule_id_not_in_the_live_rule_table(tmp_path):
    sigma_dir, runbooks_dir = _copy_trees(tmp_path)
    stray = sigma_dir / "NOT_A_REAL_RULE.yml"
    stray.write_text(
        yaml.safe_dump({
            "id": "NOT_A_REAL_RULE",
            "falsepositives": ["x" * 50],
            "runbook": "runbooks/NEW_EXEC_CONTROL_HOST.md",
        }),
        encoding="utf-8",
    )

    violations = check_rules(sigma_dir, runbooks_dir)

    assert len(violations) == 1
    assert violations[0].rule_id == "NOT_A_REAL_RULE"
    assert "not in the live rule table" in violations[0].reason
