# Runbook: Missed patch window

Rule: `MISSED_PATCH_WINDOW` | ATT&CK: T1210 (Exploitation of Remote Services, disclosed stretch) | Severity: medium

## Triage

1. Identify the closed patch window's ticket number and target host.
2. Check the host's own local patch log (outside the telemetry pipeline)
   for evidence the patch actually installed.
3. Check whether the host's telemetry agent itself was offline during the
   window (the documented false positive below).

## Containment

No immediate containment action is required; this rule reports an
absence of evidence, not an active intrusion. Treat the host as unpatched
until confirmed otherwise.

## Remediation

1. If the patch genuinely did not install, re-open the change ticket and
   schedule a new window.
2. If the telemetry agent was the gap, file a ticket to fix the agent's
   own patch-order dependency so this does not recur.
3. Track the host as exposed to whatever the missed patch addressed until
   the next window closes successfully.

## Escalation

Escalate to the patch management team lead if the same host misses two
consecutive windows for the same ticket.

## Documented false-positive case

A patch that genuinely installed but whose telemetry agent was itself
offline for the duration of the window (a chicken-and-egg case: the agent
update was part of the patch) triggers this rule. Cross-check the host's
own patch log or a follow-up telemetry heartbeat before escalating as a
missed patch.
