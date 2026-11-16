# Runbook: Removable media backstage

Rule: `REMOVABLE_MEDIA_BACKSTAGE` | ATT&CK: T1200 (Hardware Additions) | Severity: medium

## Triage

1. Identify the exact backstage host and device descriptor from the
   triggering EventID 6416 line.
2. Check the badge-access log for the host's physical location around the
   event timestamp.
3. Check for an open or recently approved work order naming that host.

## Containment

1. If no technician badge swipe and no work order correlate, treat the
   device as untrusted: do not allow any file copy off the device, and
   disable the USB port at the OS policy level if the device is still
   attached.
2. Image the device's contents (read-only) before removal if it is still
   physically present.

## Remediation

1. Re-enable the USB port once the device is confirmed benign or removed.
2. If the device carried a file that was executed, follow the
   `NEW_EXEC_CONTROL_HOST` runbook for the resulting process.
3. Remind the backstage team of the badge-and-work-order procedure if the
   access was legitimate but undocumented.

## Escalation

Escalate to the physical security team if the badge log shows no one
should have had access to the host at that time.

## Documented false-positive case

A backstage technician's badge-issued USB drive used to sideload a vendor
driver update during an unscheduled, verbally-approved visit (common when
a published window is still being filed) triggers this rule legitimately.
Confirm the technician's badge swipe and work order before closing as
benign.
