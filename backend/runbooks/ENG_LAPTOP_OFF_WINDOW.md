# Runbook: Engineering laptop reaching a controller off-window

Rule: `ENG_LAPTOP_OFF_WINDOW` | ATT&CK: T1021 (Remote Services) | Severity: medium

## Triage

1. Identify the engineering laptop's asset tag and the controller it
   reached from the triggering netconn line.
2. Check whether the laptop's assigned engineer has an open change ticket
   for that controller.
3. Check whether a maintenance window for that controller just closed
   (a late verification pass is the documented false positive below).

## Containment

1. If the connection is unauthorized, block the laptop's MAC/IP at the
   switch ACL for the controller's VLAN.
2. Require the laptop be re-authenticated to the engineering network
   before it is allowed to reach any controller again.

## Remediation

1. Review the engineer's access scope; tighten it if the laptop should
   not have reached that specific controller at all.
2. Extend or backfill the maintenance window if the access was
   authorized work that simply ran past the published end time.

## Escalation

Escalate to the attraction's engineering supervisor to confirm the
laptop's assignment and the engineer's whereabouts at the time of the
connection.

## Documented false-positive case

An engineer validating a fix immediately after a maintenance window
closed, before the published window's end time was extended on the
calendar to cover the verification pass, triggers this rule legitimately.
Confirm against the engineer's own change ticket and extend the window
retroactively if the work was authorized.
