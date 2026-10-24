"""MITRE ATT&CK Enterprise technique mapping, one per named rule.

Seven of the nine are direct behavioral matches. Two are disclosed,
deliberate stretches rather than hidden as exact (see `imperfect` below and
README Findings): ATT&CK has no technique for "a scheduled patch did not
happen" or "a host's own clock is wrong", because both are absence-of-event
or integrity-of-telemetry conditions, not an adversary action. Each is
mapped to the closest real technique instead of invented or left blank, and
the gap is named rather than smoothed over.
"""
from __future__ import annotations

from dataclasses import dataclass

from .rules import RULES


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    technique_name: str
    tactic: str
    imperfect: bool = False
    note: str = ""


ATTACK_MAPPING: dict[str, AttackMapping] = {
    "NEW_EXEC_CONTROL_HOST": AttackMapping(
        "T1204.002", "User Execution: Malicious File", "Execution",
    ),
    "REMOVABLE_MEDIA_BACKSTAGE": AttackMapping(
        "T1200", "Hardware Additions", "Initial Access",
    ),
    "ENG_LAPTOP_OFF_WINDOW": AttackMapping(
        "T1021", "Remote Services", "Lateral Movement",
    ),
    "MISSED_PATCH_WINDOW": AttackMapping(
        "T1210", "Exploitation of Remote Services", "Lateral Movement",
        imperfect=True,
        note=(
            "ATT&CK has no technique for 'a patch did not happen'; T1210 is "
            "the technique the missing patch leaves exploitable, not a "
            "behavior this rule directly observes."
        ),
    ),
    "CLOCK_DRIFT": AttackMapping(
        "T1070.006", "Indicator Removal: Timestomp", "Defense Evasion",
        imperfect=True,
        note=(
            "Timestomp is adversary tampering with file timestamps; a "
            "drifted host clock is the closest ATT&CK neighbor for a "
            "timestamp-integrity problem, not the same mechanism."
        ),
    ),
    "UNEXPECTED_SERVICE_LOGON": AttackMapping(
        "T1078", "Valid Accounts", "Privilege Escalation",
    ),
    "CONTROL_HOST_REBOOT_OFF_WINDOW": AttackMapping(
        "T1529", "System Shutdown/Reboot", "Impact",
    ),
    "ISOLATED_HOST_OUTBOUND": AttackMapping(
        "T1071", "Application Layer Protocol", "Command and Control",
    ),
    "REPEATED_FAILED_AUTH_HMI": AttackMapping(
        "T1110.001", "Brute Force: Password Guessing", "Credential Access",
    ),
}


def mapping_for(rule_id: str) -> AttackMapping:
    return ATTACK_MAPPING[rule_id]


assert set(ATTACK_MAPPING) == {r.rule_id for r in RULES}, "every rule needs exactly one ATT&CK mapping"
