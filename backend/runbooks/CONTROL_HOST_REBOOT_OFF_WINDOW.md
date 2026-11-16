# Runbook: Control host reboot outside window

Rule: `CONTROL_HOST_REBOOT_OFF_WINDOW` | ATT&CK: T1529 (System Shutdown/Reboot) | Severity: medium

## Triage

1. Identify the host and whether the restart was planned (EventID 1074)
   or unexpected (EventID 6008).
2. Check `patch_installed` telemetry for the same host around the same
   timestamp (the documented false positive below).
3. Check whether a maintenance window for the host closed shortly before
   the restart.

## Containment

No immediate containment action for a planned restart with a correlating
patch event. For an unexpected restart with no correlating event, treat
the host as having an unverified state: do not trust its last-known
configuration until re-verified.

## Remediation

1. Re-verify the host's configuration and running services after any
   unexplained restart.
2. If the restart was a delayed update-completion timer, extend the
   maintenance window's end time retroactively to cover the real restart
   time.

## Escalation

Escalate to the OT engineering lead for any unexpected (EventID 6008)
restart on a safety-critical controller.

## Documented false-positive case

A control host automatically rebooting to complete a Windows update that
installed cleanly inside the window but whose restart timer rolled past
the published window's end time triggers this rule. Confirm the
patch_installed telemetry for the same host and window before escalating.
