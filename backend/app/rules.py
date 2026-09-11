"""The nine named detection rules.

Each rule is metadata only here; the evaluation logic lives independently
in engine.py (primary) and reference_engine.py (oracle), which each read
this table for id/name/description but implement the actual event-matching
and calendar-scoring differently on purpose.

`window_aware=True` means the rule is suppressed when the triggering event
falls inside a published maintenance window for that host (or attraction,
for host="*" windows): the same event type is not an incident inside the
window and is an incident outside it. `window_aware=False` rules still
consult the calendar (the window_state is recorded on every alert either
way) but are never suppressed by it, because the condition they detect
must not happen even during maintenance (isolation breach, brute force)
or is itself a statement about the calendar (a missed patch window).
"""
from __future__ import annotations

from .models import RuleDef

RULES: list[RuleDef] = [
    RuleDef(
        rule_id="NEW_EXEC_CONTROL_HOST",
        name="New executable on a control host",
        description=(
            "A process started on a control host whose SHA-256 is not in the "
            "host's known-good baseline. Suppressed inside a maintenance "
            "window (deployments happen then); an incident outside one."
        ),
        window_aware=True,
    ),
    RuleDef(
        rule_id="REMOVABLE_MEDIA_BACKSTAGE",
        name="Removable media backstage",
        description=(
            "A removable storage device was recognized (Windows EventID "
            "6416) on a backstage host. Suppressed inside a maintenance "
            "window (technicians use USB media to transfer patches then); "
            "an incident outside one."
        ),
        window_aware=True,
    ),
    RuleDef(
        rule_id="ENG_LAPTOP_OFF_WINDOW",
        name="Engineering laptop reaching a controller off-window",
        description=(
            "An engineering laptop opened a connection to a control host. "
            "Suppressed inside a maintenance window for that controller; "
            "an incident outside one."
        ),
        window_aware=True,
    ),
    RuleDef(
        rule_id="MISSED_PATCH_WINDOW",
        name="Missed patch window",
        description=(
            "A published patch-type maintenance window closed with no "
            "matching patch_installed telemetry event recorded on the "
            "target host during the window. Evaluated once per closed "
            "patch window, not per event."
        ),
        window_aware=False,
    ),
    RuleDef(
        rule_id="CLOCK_DRIFT",
        name="Clock drift",
        description=(
            "A host's self-reported clock differs from the collector's "
            "receive time by more than 120 seconds. Never suppressed: a "
            "drifted clock is a problem on a maintenance day too, because "
            "it poisons every other timestamp-based control for that host."
        ),
        window_aware=False,
    ),
    RuleDef(
        rule_id="UNEXPECTED_SERVICE_LOGON",
        name="Unexpected service account logon",
        description=(
            "A service account (svc_*) logged on interactively or via "
            "remote desktop (LogonType 2 or 10) to a control host. "
            "Suppressed inside a maintenance window; an incident outside "
            "one."
        ),
        window_aware=True,
    ),
    RuleDef(
        rule_id="CONTROL_HOST_REBOOT_OFF_WINDOW",
        name="Control host reboot outside window",
        description=(
            "A control host logged a planned (EventID 1074) or unexpected "
            "(EventID 6008) restart. Suppressed inside a maintenance "
            "window; an incident outside one."
        ),
        window_aware=True,
    ),
    RuleDef(
        rule_id="ISOLATED_HOST_OUTBOUND",
        name="Outbound connection from an isolated control host",
        description=(
            "A control host, which should never originate traffic outside "
            "the attraction's private range, opened a connection to an "
            "address outside 10.20.0.0/16. Never suppressed: isolation is "
            "not relaxed for maintenance, engineers connect in over the "
            "engineering-laptop path instead."
        ),
        window_aware=False,
    ),
    RuleDef(
        rule_id="REPEATED_FAILED_AUTH_HMI",
        name="Repeated failed authentication on an HMI",
        description=(
            "Three or more failed logons (EventID 4625) on the same HMI "
            "host within a 10-minute span. Never suppressed: a credential "
            "guessing attempt is not made acceptable by a maintenance "
            "window."
        ),
        window_aware=False,
    ),
]

RULES_BY_ID = {r.rule_id: r for r in RULES}

assert len(RULES) == 9, "exactly nine named rules"
