"""Primary detection engine: pandas-indexed, evaluates all nine rules over
a DataFrame of events plus the maintenance calendar.

This is one of the two independently coded implementations in this repo.
See reference_engine.py for the second, a plain-loop implementation with
no pandas and no shared helper functions, used as the oracle in
tests/test_oracle_diff.py. The two must agree exactly on every alert.
"""
from __future__ import annotations

from datetime import timedelta

import pandas as pd

from .models import Alert
from .rules import RULES_BY_ID

DRIFT_THRESHOLD_SECONDS = 120
FAILED_AUTH_COUNT = 3
FAILED_AUTH_WINDOW_MINUTES = 10
ISOLATED_PREFIX = "10.20."


def _events_to_frame(events) -> pd.DataFrame:
    rows = [
        {
            "event": e,
            "event_id": e.event_id,
            "source": e.source,
            "host": e.host,
            "attraction": e.attraction,
            "ts": e.ts,
            "kind": e.kind,
        }
        for e in events
    ]
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("ts").reset_index(drop=True)
    return df


def _window_at(calendar, attraction, host, ts):
    for w in calendar:
        if w.attraction == attraction and (w.host == host or w.host == "*"):
            if w.start <= ts <= w.end:
                return w
    return None


def _mk_alert(rule_id, host, attraction, ts, lines, explanation, window_state, pid=None, ppid=None):
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


class PrimaryEngine:
    name = "primary-vectorized"

    def evaluate(self, events, calendar, known_good_hashes, as_of=None) -> list:
        df = _events_to_frame(events)
        alerts: list = []
        if df.empty:
            return alerts
        as_of = as_of or df["ts"].max()

        alerts += self._new_exec(df, calendar, known_good_hashes)
        alerts += self._removable_media(df, calendar)
        alerts += self._eng_laptop(df, calendar)
        alerts += self._missed_patch(calendar, df, as_of)
        alerts += self._clock_drift(df, calendar)
        alerts += self._service_logon(df, calendar)
        alerts += self._reboot(df, calendar)
        alerts += self._isolated_outbound(df)
        alerts += self._repeated_failed_auth(df)

        alerts.sort(key=lambda a: (a.ts, a.rule_id, a.host))
        return alerts

    def _new_exec(self, df, calendar, known_good_hashes):
        out = []
        mask = df["kind"] == "process_start"
        for _, row in df[mask].iterrows():
            e = row["event"]
            good = known_good_hashes.get(e.host, set())
            if e.fields.get("sha256") in good:
                continue
            w = _window_at(calendar, e.attraction, e.host, e.ts)
            if w is not None:
                continue
            out.append(
                _mk_alert(
                    "NEW_EXEC_CONTROL_HOST", e.host, e.attraction, e.ts, [e.raw],
                    f"Unrecognized executable hash {e.fields.get('sha256')} started "
                    f"on control host {e.host} outside any maintenance window.",
                    "out_of_window",
                    pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                )
            )
        return out

    def _removable_media(self, df, calendar):
        out = []
        mask = df["kind"] == "device_added"
        for _, row in df[mask].iterrows():
            e = row["event"]
            if not e.host.startswith("BACKSTAGE-"):
                continue
            w = _window_at(calendar, e.attraction, e.host, e.ts)
            if w is not None:
                continue
            out.append(
                _mk_alert(
                    "REMOVABLE_MEDIA_BACKSTAGE", e.host, e.attraction, e.ts, [e.raw],
                    f"Removable device recognized on backstage host {e.host} outside "
                    "any maintenance window.",
                    "out_of_window",
                    pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                )
            )
        return out

    def _eng_laptop(self, df, calendar):
        out = []
        mask = df["kind"] == "netconn"
        for _, row in df[mask].iterrows():
            e = row["event"]
            src = e.fields.get("src", "")
            dst = e.fields.get("dst", "")
            if not src.startswith("ENG-LAPTOP"):
                continue
            if not dst.startswith("CTRL-"):
                continue
            w = _window_at(calendar, e.attraction, dst, e.ts)
            if w is not None:
                continue
            out.append(
                _mk_alert(
                    "ENG_LAPTOP_OFF_WINDOW", dst, e.attraction, e.ts, [e.raw],
                    f"Engineering laptop {src} reached controller {dst} outside "
                    "any maintenance window.",
                    "out_of_window",
                    pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                )
            )
        return out

    def _missed_patch(self, calendar, df, as_of):
        out = []
        patched = df[df["kind"] == "patch_installed"]
        for w in calendar:
            if w.window_type != "patch" or w.host == "*":
                continue
            if w.end > as_of:
                continue  # window has not closed yet as of this evaluation
            hit = patched[
                (patched["host"] == w.host)
                & (patched["ts"] >= w.start)
                & (patched["ts"] <= w.end)
            ]
            if not hit.empty:
                continue
            out.append(
                _mk_alert(
                    "MISSED_PATCH_WINDOW", w.host, w.attraction, w.end,
                    [f"maintenance_calendar: window {w.window_id} ({w.ticket}) "
                     f"for {w.host} closed {w.start.isoformat()}-{w.end.isoformat()} "
                     "with no patch_installed telemetry event on record"],
                    f"Patch window {w.window_id} for {w.host} closed with no "
                    "matching patch_installed event.",
                    "not_applicable",
                )
            )
        return out

    def _clock_drift(self, df, calendar):
        out = []
        mask = df["kind"] == "clock_check"
        for _, row in df[mask].iterrows():
            e = row["event"]
            host_ts = pd.Timestamp(e.fields["host_ts"].rstrip("Z"))
            drift = abs((e.ts - host_ts.to_pydatetime()).total_seconds())
            if drift <= DRIFT_THRESHOLD_SECONDS:
                continue
            out.append(
                _mk_alert(
                    "CLOCK_DRIFT", e.host, e.attraction, e.ts, [e.raw],
                    f"Host {e.host} clock drifted {drift:.0f}s from the collector's "
                    "receive time.",
                    _window_at(calendar, e.attraction, e.host, e.ts) and "in_window" or "out_of_window",
                    pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                )
            )
        return out

    def _service_logon(self, df, calendar):
        out = []
        mask = (df["kind"] == "logon") & df["event"].apply(
            lambda e: str(e.fields.get("TargetUserName", "")).startswith("svc_")
            and e.fields.get("LogonType") in (2, 10)
        )
        for _, row in df[mask].iterrows():
            e = row["event"]
            w = _window_at(calendar, e.attraction, e.host, e.ts)
            if w is not None:
                continue
            out.append(
                _mk_alert(
                    "UNEXPECTED_SERVICE_LOGON", e.host, e.attraction, e.ts, [e.raw],
                    f"Service account {e.fields.get('TargetUserName')} logged on "
                    f"interactively (LogonType {e.fields.get('LogonType')}) to "
                    f"{e.host} outside any maintenance window.",
                    "out_of_window",
                    pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                )
            )
        return out

    def _reboot(self, df, calendar):
        out = []
        mask = df["kind"].isin(["restart_planned", "restart_unexpected"])
        for _, row in df[mask].iterrows():
            e = row["event"]
            if not e.host.startswith("CTRL-"):
                continue
            w = _window_at(calendar, e.attraction, e.host, e.ts)
            if w is not None:
                continue
            out.append(
                _mk_alert(
                    "CONTROL_HOST_REBOOT_OFF_WINDOW", e.host, e.attraction, e.ts, [e.raw],
                    f"Control host {e.host} restarted ({e.kind}) outside any "
                    "maintenance window.",
                    "out_of_window",
                    pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                )
            )
        return out

    def _isolated_outbound(self, df):
        out = []
        mask = df["kind"] == "netconn"
        for _, row in df[mask].iterrows():
            e = row["event"]
            src = e.fields.get("src", "")
            dst = e.fields.get("dst", "")
            if not src.startswith("CTRL-"):
                continue
            if dst.startswith(ISOLATED_PREFIX) or dst.startswith("ENG-LAPTOP") or dst.startswith("CTRL-"):
                continue
            out.append(
                _mk_alert(
                    "ISOLATED_HOST_OUTBOUND", src, e.attraction, e.ts, [e.raw],
                    f"Isolated control host {src} opened a connection to {dst}, "
                    "outside the attraction's private range.",
                    "not_applicable",
                    pid=e.fields.get("pid"), ppid=e.fields.get("ppid"),
                )
            )
        return out

    def _repeated_failed_auth(self, df):
        out = []
        mask = df["kind"] == "logon_failed"
        sub = df[mask]
        for host, group in sub.groupby("host"):
            if not host.startswith("HMI-"):
                continue
            events_sorted = sorted(group["event"].tolist(), key=lambda e: e.ts)
            window = FAILED_AUTH_WINDOW_MINUTES
            i = 0
            n = len(events_sorted)
            while i < n:
                bucket = [events_sorted[i]]
                j = i + 1
                while j < n and (events_sorted[j].ts - bucket[0].ts) <= timedelta(minutes=window):
                    bucket.append(events_sorted[j])
                    j += 1
                if len(bucket) >= FAILED_AUTH_COUNT:
                    e0 = bucket[0]
                    out.append(
                        _mk_alert(
                            "REPEATED_FAILED_AUTH_HMI", host, e0.attraction, bucket[-1].ts,
                            [b.raw for b in bucket],
                            f"{len(bucket)} failed logons on HMI {host} within "
                            f"{window} minutes.",
                            "not_applicable",
                            pid=e0.fields.get("pid"), ppid=e0.fields.get("ppid"),
                        )
                    )
                    i = j
                else:
                    i += 1
        return out
