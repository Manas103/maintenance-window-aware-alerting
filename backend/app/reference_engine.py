"""Reference (oracle) detection engine.

Deliberately coded differently from engine.PrimaryEngine: plain Python
lists and dicts, one straightforward pass per rule over events sorted in
memory, no pandas, no shared helper functions with the primary engine.
The two are diffed exactly, alert for alert, in
tests/test_oracle_diff.py. Any disagreement is a bug in one of them.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from .models import Alert
from .rules import RULES_BY_ID

_DRIFT_THRESHOLD_SECONDS = 120
_FAILED_AUTH_COUNT = 3
_FAILED_AUTH_WINDOW = timedelta(minutes=10)
_ISOLATED_PREFIX = "10.20."


def _window_for(calendar, attraction, host, ts):
    for w in calendar:
        if w.attraction != attraction:
            continue
        if w.host != host and w.host != "*":
            continue
        if w.start <= ts <= w.end:
            return w
    return None


def _alert(rule_id, host, attraction, ts, lines, explanation, window_state, pid=None, ppid=None):
    rule = RULES_BY_ID[rule_id]
    return Alert(
        alert_id=f"{rule_id}|{host}|{ts.isoformat()}",
        rule_id=rule_id,
        rule_name=rule.name,
        host=host,
        attraction=attraction,
        ts=ts,
        triggering_lines=tuple(lines),
        explanation=explanation,
        window_state=window_state,
        pid=pid,
        ppid=ppid,
    )


class ReferenceEngine:
    name = "reference-linear"

    def evaluate(self, events, calendar, known_good_hashes, as_of=None):
        ordered = sorted(events, key=lambda e: e.ts)
        if not ordered:
            return []
        as_of = as_of or ordered[-1].ts

        alerts = []
        by_host = defaultdict(list)
        for e in ordered:
            by_host[e.host].append(e)

        for e in ordered:
            if e.kind == "process_start":
                good = known_good_hashes.get(e.host, set())
                if e.fields.get("sha256") not in good:
                    if _window_for(calendar, e.attraction, e.host, e.ts) is None:
                        alerts.append(_alert(
                            "NEW_EXEC_CONTROL_HOST", e.host, e.attraction, e.ts,
                            [e.raw],
                            f"Unrecognized executable hash on {e.host} outside a window.",
                            "out_of_window",
                            pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                        ))

            elif e.kind == "device_added" and e.host.startswith("BACKSTAGE-"):
                if _window_for(calendar, e.attraction, e.host, e.ts) is None:
                    alerts.append(_alert(
                        "REMOVABLE_MEDIA_BACKSTAGE", e.host, e.attraction, e.ts,
                        [e.raw],
                        f"Removable device recognized on {e.host} outside a window.",
                        "out_of_window",
                        pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                    ))

            elif e.kind == "netconn":
                src = e.fields.get("src", "")
                dst = e.fields.get("dst", "")
                if src.startswith("ENG-LAPTOP") and dst.startswith("CTRL-"):
                    if _window_for(calendar, e.attraction, dst, e.ts) is None:
                        alerts.append(_alert(
                            "ENG_LAPTOP_OFF_WINDOW", dst, e.attraction, e.ts,
                            [e.raw],
                            f"Engineering laptop {src} reached {dst} outside a window.",
                            "out_of_window",
                            pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                        ))
                if src.startswith("CTRL-"):
                    is_internal = (
                        dst.startswith(_ISOLATED_PREFIX)
                        or dst.startswith("ENG-LAPTOP")
                        or dst.startswith("CTRL-")
                    )
                    if not is_internal:
                        alerts.append(_alert(
                            "ISOLATED_HOST_OUTBOUND", src, e.attraction, e.ts,
                            [e.raw],
                            f"Isolated host {src} connected outside the private range to {dst}.",
                            "not_applicable",
                            pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                        ))

            elif e.kind == "clock_check":
                host_ts_str = e.fields["host_ts"].rstrip("Z")
                host_ts = datetime.fromisoformat(host_ts_str)
                drift_seconds = (e.ts - host_ts).total_seconds()
                if drift_seconds < 0:
                    drift_seconds = -drift_seconds
                if drift_seconds > _DRIFT_THRESHOLD_SECONDS:
                    w = _window_for(calendar, e.attraction, e.host, e.ts)
                    alerts.append(_alert(
                        "CLOCK_DRIFT", e.host, e.attraction, e.ts, [e.raw],
                        f"Clock drift of {drift_seconds:.0f}s on {e.host}.",
                        "in_window" if w else "out_of_window",
                        pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                    ))

            elif e.kind == "logon":
                user = str(e.fields.get("TargetUserName", ""))
                logon_type = e.fields.get("LogonType")
                if user.startswith("svc_") and logon_type in (2, 10):
                    if _window_for(calendar, e.attraction, e.host, e.ts) is None:
                        alerts.append(_alert(
                            "UNEXPECTED_SERVICE_LOGON", e.host, e.attraction, e.ts,
                            [e.raw],
                            f"Service account {user} logged on interactively to {e.host}.",
                            "out_of_window",
                            pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                        ))

            elif e.kind in ("restart_planned", "restart_unexpected") and e.host.startswith("CTRL-"):
                if _window_for(calendar, e.attraction, e.host, e.ts) is None:
                    alerts.append(_alert(
                        "CONTROL_HOST_REBOOT_OFF_WINDOW", e.host, e.attraction, e.ts,
                        [e.raw],
                        f"Control host {e.host} restarted outside a window.",
                        "out_of_window",
                        pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                    ))

        # Repeated failed auth: separate pass, needs the full per-host
        # sequence rather than a single-event view.
        for host, host_events in by_host.items():
            if not host.startswith("HMI-"):
                continue
            fails = [e for e in host_events if e.kind == "logon_failed"]
            fails.sort(key=lambda e: e.ts)
            i = 0
            while i < len(fails):
                bucket = [fails[i]]
                k = i + 1
                while k < len(fails) and (fails[k].ts - bucket[0].ts) <= _FAILED_AUTH_WINDOW:
                    bucket.append(fails[k])
                    k += 1
                if len(bucket) >= _FAILED_AUTH_COUNT:
                    alerts.append(_alert(
                        "REPEATED_FAILED_AUTH_HMI", host, bucket[0].attraction, bucket[-1].ts,
                        [b.raw for b in bucket],
                        f"{len(bucket)} failed logons on {host} within 10 minutes.",
                        "not_applicable",
                        pid=bucket[0].fields.get("pid"), ppid=bucket[0].fields.get("ppid"),
                    ))
                    i = k
                else:
                    i += 1

        # Missed patch windows: a calendar-only pass, not an event pass.
        patch_events_by_host = defaultdict(list)
        for e in ordered:
            if e.kind == "patch_installed":
                patch_events_by_host[e.host].append(e)
        for w in calendar:
            if w.window_type != "patch" or w.host == "*":
                continue
            if w.end > as_of:
                continue
            found = False
            for e in patch_events_by_host.get(w.host, []):
                if w.start <= e.ts <= w.end:
                    found = True
                    break
            if not found:
                alerts.append(_alert(
                    "MISSED_PATCH_WINDOW", w.host, w.attraction, w.end,
                    [f"maintenance_calendar: window {w.window_id} ({w.ticket}) for "
                     f"{w.host} closed {w.start.isoformat()}-{w.end.isoformat()} with "
                     "no patch_installed telemetry event on record"],
                    f"Patch window {w.window_id} for {w.host} closed unpatched.",
                    "not_applicable",
                ))

        alerts.sort(key=lambda a: (a.ts, a.rule_id, a.host))
        return alerts
