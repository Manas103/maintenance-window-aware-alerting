# Runbook: Clock drift

Rule: `CLOCK_DRIFT` | ATT&CK: T1070.006 (Indicator Removal: Timestomp, disclosed stretch) | Severity: low

## Triage

1. Identify the host and the measured drift in seconds from the
   triggering `clock_check` line.
2. Check the host's NTP service state and last successful sync time.
3. Check whether the host recently resumed from sleep/hibernate (the
   documented false positive below).

## Containment

No containment action; a drifted clock is not itself an active intrusion,
but every other rule's timestamp comparisons for this host should be
treated as unreliable until the drift is corrected.

## Remediation

1. Force an NTP resync on the host.
2. Re-run clock_check on the next telemetry cycle to confirm drift has
   returned under the 120-second threshold.
3. If NTP is reachable and synced but drift persists, escalate as a
   possible deliberate timestamp manipulation.

## Escalation

Escalate to the SOC analyst on duty if drift persists after a confirmed
NTP resync, since that pattern is consistent with deliberate timestamp
manipulation rather than an ordinary sync lag.

## Documented false-positive case

A host that just rejoined the network after a long sleep/hibernate cycle
and has not yet completed its first NTP sync triggers this rule. Confirm
the host's NTP service state and re-check drift a few minutes later
before escalating.
