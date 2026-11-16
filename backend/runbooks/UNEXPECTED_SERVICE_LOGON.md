# Runbook: Unexpected service account logon

Rule: `UNEXPECTED_SERVICE_LOGON` | ATT&CK: T1078 (Valid Accounts) | Severity: high

## Triage

1. Identify the service account name and LogonType from the triggering
   line.
2. Check the helpdesk ticket queue for a matching emergency-access
   lockout record (the documented false positive below).
3. Check whether the service account's normal use is non-interactive
   (scheduled task, API) to confirm this logon type is genuinely
   anomalous for it.

## Containment

1. Force-expire the service account's active session.
2. Disable the service account temporarily if no matching ticket exists.

## Remediation

1. Rotate the service account's credentials regardless of the outcome.
2. Re-enable the account only after confirming no unauthorized action was
   taken during the session.
3. If the access was a legitimate emergency, document the exception and
   require a follow-up credential rotation within 24 hours.

## Escalation

Escalate to the identity and access management team immediately; a
service account logging on interactively is a privilege-escalation
pattern regardless of intent.

## Documented false-positive case

An administrator deliberately using a service account's credentials for
an emergency interactive session when their own account is locked out
triggers this rule. Confirm against the helpdesk ticket for the lockout
before closing as benign, and rotate the service account's credentials
afterward regardless.
