# Runbook: Outbound connection from an isolated control host

Rule: `ISOLATED_HOST_OUTBOUND` | ATT&CK: T1071 (Application Layer Protocol) | Severity: critical

## Triage

1. Identify the source control host and the destination address from the
   triggering netconn line.
2. Check the network change log for a recent re-addressing of a DNS/NTP
   relay the host legitimately depends on (the documented false positive
   below).
3. If no correlating change exists, treat this as a live command-and-
   control indicator.

## Containment

1. Isolate the control host's network segment immediately; this rule is
   never suppressed by a maintenance window for a reason, so do not wait
   for calendar confirmation.
2. Block the destination address at the perimeter firewall.
3. Preserve a packet capture of the connection if the capture pipeline is
   still running.

## Remediation

1. Re-image the control host from a known-good baseline if the
   destination cannot be attributed to an authorized relay.
2. If the destination was a legitimately re-addressed relay, correct the
   isolation allowlist and document the change.

## Escalation

Escalate to the SOC incident commander immediately; this is the highest
severity rule in the library because isolated-control-host egress is the
single clearest signal of an active breach on the OT floor.

## Documented false-positive case

A control host resolving a name through a DNS or NTP relay that was
recently re-addressed outside 10.20.0.0/16 without updating the isolation
allowlist triggers this rule. Confirm against the network change log
before escalating, and correct the allowlist either way.
