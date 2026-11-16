# Runbook: Repeated failed authentication on an HMI

Rule: `REPEATED_FAILED_AUTH_HMI` | ATT&CK: T1110.001 (Brute Force: Password Guessing) | Severity: high

## Triage

1. Identify the HMI host and the number of failed logons within the
   10-minute window from the triggering lines.
2. Check the password-rotation log for a recent change to the account
   being guessed (the documented false positive below).
3. Check whether a single username or multiple usernames were targeted;
   multiple usernames is a stronger brute-force signal.

## Containment

1. Lock the targeted account after the threshold is crossed if it is not
   already locked by policy.
2. If the attempts continue from the same source after the lockout,
   isolate the HMI's network segment.

## Remediation

1. Reset the account's credentials regardless of outcome.
2. Review the HMI's logon policy for lockout threshold and backoff
   settings if this is a recurring pattern.

## Escalation

Escalate to the SOC analyst on duty immediately; repeated failed
authentication on an HMI is never suppressed by a maintenance window and
should be treated as a live credential-guessing attempt until ruled out.

## Documented false-positive case

A shift operator who forgot a recently rotated HMI password and retried
it several times in a row before calling the helpdesk triggers this rule.
Confirm against the password-rotation log and the helpdesk ticket
timestamp before escalating.
