# Runbook: New executable on a control host

Rule: `NEW_EXEC_CONTROL_HOST` | ATT&CK: T1204.002 (User Execution: Malicious File) | Severity: high

## Triage

1. Pull the triggering line from the alert and read the `sha256`, `host`,
   and process path fields.
2. Check the hash against the host's known-good baseline
   (`known_good_hashes` in the seed data) and against the change-ticket
   log for a matching emergency patch record.
3. If a matching change ticket exists, this is the documented false
   positive below; otherwise treat as a live incident.

## Containment

1. Isolate the control host's network segment at the switch (do not power
   it off; a live memory image may be needed).
2. Suspend the process if it is still running, without deleting the
   binary.
3. Preserve the binary and its hash for later analysis.

## Remediation

1. Re-image the host from the last known-good baseline if the hash cannot
   be attributed to an authorized source.
2. Add the hash to the known-good baseline only after it is confirmed
   benign and tied to a real change ticket.
3. File or backfill a maintenance window if the work was authorized but
   the window was missed.

## Escalation

Escalate to the OT security lead immediately if the host is a
safety-critical controller (any `CTRL-` host serving a ride's stop
circuit); otherwise escalate to the on-call SOC analyst within the
standard SLA.

## Documented false-positive case

A documented emergency vendor patch pushed outside a published
maintenance window (no change ticket filed in time for the calendar)
triggers this rule legitimately. Verify against the change-ticket log
before closing as benign, and backfill a maintenance window if the patch
was authorized.
