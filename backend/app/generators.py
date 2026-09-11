"""Synthetic log and calendar generators.

Everything this module produces is disclosed synthetic data: no real
Disney, vendor or attraction system was observed or reproduced. Hostnames,
attraction names and the maintenance schedule are invented for this repo.

Three source shapes are produced, matching the resume claim:
  - "winevt": Windows Security/System event log entries, shaped like the
    JSON you get back from `Get-WinEvent | ConvertTo-Json`, one event per
    line.
  - "syslog": RFC 3164-style Linux syslog lines.
  - "process": endpoint process telemetry (process start/stop, patch
    installs, periodic clock checks), one JSON object per line.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta

from .models import LogEvent, MaintenanceWindow

BASE_DATE = datetime(2026, 6, 1, 0, 0, 0)
SUBNET_PREFIX = "10.20."  # everything inside the attractions' private range

ATTRACTIONS = {
    "space-voyager": {
        "control": ["CTRL-SPACEVOY-01", "CTRL-SPACEVOY-02"],
        "hmi": ["HMI-SPACEVOY-01"],
        "backstage": ["BACKSTAGE-SPACEVOY-01"],
        "eng_laptop": "ENG-LAPTOP-01",
    },
    "jungle-trek": {
        "control": ["CTRL-JUNGLETREK-01"],
        "hmi": ["HMI-JUNGLETREK-01"],
        "backstage": ["BACKSTAGE-JUNGLETREK-01"],
        "eng_laptop": "ENG-LAPTOP-02",
    },
}


def _hash_for(seed_text: str) -> str:
    return hashlib.sha256(seed_text.encode()).hexdigest()


def known_good_hashes() -> dict:
    """Baseline of known-good executable hashes per control host."""
    out = {}
    for attraction, cfg in ATTRACTIONS.items():
        for host in cfg["control"]:
            out[host] = {
                _hash_for(f"{host}:plc_runtime.exe"),
                _hash_for(f"{host}:diagnostics_agent.exe"),
            }
    return out


def _seq_counter():
    n = [0]

    def nxt():
        n[0] += 1
        return n[0]

    return nxt


class _EventFactory:
    """Small helper so every generator function makes ids/raw text the
    same way without the two engines sharing any evaluation code."""

    def __init__(self):
        self._n = _seq_counter()

    def winevt(self, attraction, host, ts, event_id, channel, **fields):
        payload = {
            "EventID": event_id,
            "Channel": channel,
            "Provider": "Microsoft-Windows-Security-Auditing"
            if channel == "Security"
            else "Microsoft-Windows-Kernel-General",
            "Computer": host,
            "TimeCreated": ts.isoformat() + "Z",
        }
        payload.update(fields)
        raw = json.dumps(payload, sort_keys=True)
        kind = {
            4624: "logon",
            4625: "logon_failed",
            6416: "device_added",
            1074: "restart_planned",
            6008: "restart_unexpected",
        }[event_id]
        return LogEvent(
            event_id=f"evt-{self._n()}",
            source="winevt",
            host=host,
            attraction=attraction,
            ts=ts,
            raw=raw,
            kind=kind,
            fields=fields,
        )

    def syslog(self, attraction, host, ts, proc, pid, msg, kind, **fields):
        stamp = ts.strftime("%b %e %H:%M:%S")
        raw = f"{stamp} {host} {proc}[{pid}]: {msg}"
        return LogEvent(
            event_id=f"evt-{self._n()}",
            source="syslog",
            host=host,
            attraction=attraction,
            ts=ts,
            raw=raw,
            kind=kind,
            fields=fields,
        )

    def process(self, attraction, host, ts, event, **fields):
        payload = {"ts": ts.isoformat() + "Z", "host": host, "event": event}
        payload.update(fields)
        raw = json.dumps(payload, sort_keys=True)
        return LogEvent(
            event_id=f"evt-{self._n()}",
            source="process",
            host=host,
            attraction=attraction,
            ts=ts,
            raw=raw,
            kind=event,
            fields=fields,
        )


def build_calendar(num_weeks: int, extra_patch_windows: list | None = None) -> list:
    """Weekly patch windows per control host (Tuesday 02:00-04:00) and a
    weekly general maintenance window per attraction (Sunday 01:00-05:00)
    covering every host, plus any explicitly requested extra windows."""
    windows = []
    n = _seq_counter()
    for week in range(num_weeks):
        week_start = BASE_DATE + timedelta(weeks=week)
        tuesday = week_start + timedelta(days=(1 - week_start.weekday()) % 7)
        sunday = week_start + timedelta(days=(6 - week_start.weekday()) % 7)
        for attraction, cfg in ATTRACTIONS.items():
            for host in cfg["control"]:
                start = tuesday.replace(hour=2, minute=0, second=0)
                end = start + timedelta(hours=2)
                windows.append(
                    MaintenanceWindow(
                        window_id=f"MW-PATCH-{n()}",
                        attraction=attraction,
                        host=host,
                        start=start,
                        end=end,
                        window_type="patch",
                        ticket=f"MW-{attraction.upper()}-{week:04d}",
                        description=f"Weekly patch window for {host}",
                    )
                )
            start = sunday.replace(hour=1, minute=0, second=0)
            end = start + timedelta(hours=4)
            windows.append(
                MaintenanceWindow(
                    window_id=f"MW-GEN-{n()}",
                    attraction=attraction,
                    host="*",
                    start=start,
                    end=end,
                    window_type="general",
                    ticket=f"MW-{attraction.upper()}-GEN-{week:04d}",
                    description=f"Weekly general maintenance window for {attraction}",
                )
            )
    if extra_patch_windows:
        windows.extend(extra_patch_windows)
    return windows


def _emit_normal_day(f: _EventFactory, attraction, cfg, day, hashes, windows_today):
    """One day of pure baseline activity for one attraction. `windows_today`
    is the list of MaintenanceWindow objects active on this attraction on
    this calendar day, used to place legitimate maintenance activity inside
    them so suppression is actually exercised, not just untested."""
    events = []
    # Routine clock checks: tiny, sub-threshold drift on every host.
    for host_list in (cfg["control"], cfg["hmi"], cfg["backstage"]):
        for host in host_list:
            ts = day.replace(hour=6, minute=0, second=0)
            host_ts = ts - timedelta(seconds=3)  # well under the 120s threshold
            events.append(
                f.process(
                    attraction,
                    host,
                    ts,
                    "clock_check",
                    host_ts=host_ts.isoformat() + "Z",
                )
            )
    # Routine known-good process starts on control hosts.
    for host in cfg["control"]:
        ts = day.replace(hour=6, minute=5, second=0)
        good_hash = sorted(hashes[host])[0]
        events.append(
            f.process(
                attraction,
                host,
                ts,
                "process_start",
                pid=4400,
                path="C:\\plc\\plc_runtime.exe",
                sha256=good_hash,
                user="SYSTEM",
            )
        )
    # Routine batch service-account logon (LogonType 5), never flagged.
    for host in cfg["control"]:
        ts = day.replace(hour=6, minute=10, second=0)
        events.append(
            f.winevt(
                attraction,
                host,
                ts,
                4624,
                "Security",
                TargetUserName="svc_telemetry",
                LogonType=5,
                IpAddress=f"{SUBNET_PREFIX}4.10",
            )
        )
    # Legitimate maintenance activity, placed inside today's windows.
    for w in windows_today:
        if w.window_type == "patch":
            mid = w.start + (w.end - w.start) / 2
            events.append(
                f.process(
                    attraction,
                    w.host,
                    mid,
                    "patch_installed",
                    kb="KB-SIM-0042",
                    result="success",
                )
            )
        elif w.window_type == "general":
            mid = w.start + timedelta(minutes=30)
            backstage_host = cfg["backstage"][0]
            events.append(
                f.winevt(
                    attraction,
                    backstage_host,
                    mid,
                    6416,
                    "System",
                    DeviceDescription="USB Mass Storage Device",
                    ClassName="DiskDrive",
                )
            )
            control_host = cfg["control"][0]
            events.append(
                f.syslog(
                    attraction,
                    "fw-" + attraction,
                    mid + timedelta(minutes=5),
                    "fw",
                    1000,
                    f"connection accepted src={cfg['eng_laptop']} "
                    f"dst={control_host} dst_port=502 proto=tcp",
                    "netconn",
                    src=cfg["eng_laptop"],
                    dst=control_host,
                )
            )
            events.append(
                f.winevt(
                    attraction,
                    control_host,
                    mid + timedelta(minutes=10),
                    4624,
                    "Security",
                    TargetUserName="svc_maint",
                    LogonType=10,
                    IpAddress=f"{SUBNET_PREFIX}4.{20}",
                )
            )
            events.append(
                f.winevt(
                    attraction,
                    control_host,
                    mid + timedelta(minutes=40),
                    1074,
                    "System",
                    ProcessName="C:\\Windows\\System32\\winlogon.exe",
                    Reason="Planned maintenance restart",
                )
            )
    return events


def _windows_active_on(calendar, attraction, day):
    day_start = day.replace(hour=0, minute=0, second=0)
    day_end = day_start + timedelta(days=1)
    out = []
    for w in calendar:
        if w.attraction != attraction:
            continue
        if w.start < day_end and w.end > day_start:
            out.append(w)
    return out


def build_clean_corpus(num_days: int = 40):
    """Exactly `num_days` full clean operating days across both
    attractions: every scheduled patch window gets patched, every piece of
    legitimate maintenance activity happens inside its window, and nothing
    else happens. This must produce zero alerts."""
    f = _EventFactory()
    hashes = known_good_hashes()
    num_weeks = (num_days // 7) + 2
    calendar = build_calendar(num_weeks)
    events = []
    for i in range(num_days):
        day = BASE_DATE + timedelta(days=i)
        for attraction, cfg in ATTRACTIONS.items():
            windows_today = _windows_active_on(calendar, attraction, day)
            events.extend(_emit_normal_day(f, attraction, cfg, day, hashes, windows_today))
    events.sort(key=lambda e: e.ts)
    return events, calendar


def build_seeded_corpus():
    """A shorter clean baseline (14 days) plus exactly 40 seeded incident
    scenarios, one alert expected per scenario, spread across the nine
    rules. Returns (events, calendar, scenarios, as_of) where `scenarios`
    is the list of dicts the tests check against and `as_of` is the
    timestamp the MISSED_PATCH_WINDOW rule should evaluate as of."""
    f = _EventFactory()
    hashes = known_good_hashes()

    # Four extra, isolated patch windows used only by the missed-patch
    # scenarios below, so the regular weekly schedule (which the baseline
    # always satisfies) is untouched.
    extra_windows = []
    missed_hosts = [
        ("space-voyager", "CTRL-SPACEVOY-01"),
        ("space-voyager", "CTRL-SPACEVOY-02"),
        ("jungle-trek", "CTRL-JUNGLETREK-01"),
        ("space-voyager", "CTRL-SPACEVOY-01"),
    ]
    for idx, (attraction, host) in enumerate(missed_hosts):
        day = BASE_DATE + timedelta(days=3 + idx * 2)
        start = day.replace(hour=2, minute=0, second=0)
        end = start + timedelta(hours=2)
        extra_windows.append(
            MaintenanceWindow(
                window_id=f"MW-MISSED-{idx}",
                attraction=attraction,
                host=host,
                start=start,
                end=end,
                window_type="patch",
                ticket=f"MW-MISSED-{idx:04d}",
                description="Ad hoc patch window used to test a missed patch",
            )
        )

    num_weeks = 3
    calendar = build_calendar(num_weeks, extra_patch_windows=extra_windows)

    events = []
    for i in range(14):
        day = BASE_DATE + timedelta(days=i)
        for attraction, cfg in ATTRACTIONS.items():
            windows_today = [
                w for w in _windows_active_on(calendar, attraction, day)
                if not w.window_id.startswith("MW-MISSED")
            ]
            events.extend(_emit_normal_day(f, attraction, cfg, day, hashes, windows_today))

    scenarios = []

    def off_window_time(day_offset, hour=14):
        # Wednesdays at 14:00 fall outside every patch (Tue 02-04) and
        # general (Sun 01-05) window in this calendar.
        return BASE_DATE + timedelta(days=day_offset, hours=hour)

    sid = _seq_counter()

    # 1) NEW_EXEC_CONTROL_HOST x5
    for i in range(5):
        attraction = "space-voyager" if i % 2 == 0 else "jungle-trek"
        cfg = ATTRACTIONS[attraction]
        host = cfg["control"][i % len(cfg["control"])]
        ts = off_window_time(9 + i, hour=10 + i)
        bad_hash = _hash_for(f"malicious-payload-{i}")
        ev = f.process(
            attraction, host, ts, "process_start",
            pid=9900 + i, path="C:\\Windows\\Temp\\update.exe",
            sha256=bad_hash, user="SYSTEM",
        )
        events.append(ev)
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "NEW_EXEC_CONTROL_HOST",
                           "host": host, "attraction": attraction, "ts": ts,
                           "events": [ev]})

    # 2) REMOVABLE_MEDIA_BACKSTAGE x5
    for i in range(5):
        attraction = "space-voyager" if i % 2 == 0 else "jungle-trek"
        cfg = ATTRACTIONS[attraction]
        host = cfg["backstage"][0]
        ts = off_window_time(9 + i, hour=11 + i)
        ev = f.winevt(
            attraction, host, ts, 6416, "System",
            DeviceDescription="USB Mass Storage Device", ClassName="DiskDrive",
        )
        events.append(ev)
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "REMOVABLE_MEDIA_BACKSTAGE",
                           "host": host, "attraction": attraction, "ts": ts,
                           "events": [ev]})

    # 3) ENG_LAPTOP_OFF_WINDOW x4
    for i in range(4):
        attraction = "space-voyager" if i % 2 == 0 else "jungle-trek"
        cfg = ATTRACTIONS[attraction]
        host = cfg["control"][0]
        ts = off_window_time(2 + i, hour=15)
        ev = f.syslog(
            attraction, "fw-" + attraction, ts, "fw", 1000 + i,
            f"connection accepted src={cfg['eng_laptop']} dst={host} "
            f"dst_port=502 proto=tcp",
            "netconn", src=cfg["eng_laptop"], dst=host,
        )
        events.append(ev)
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "ENG_LAPTOP_OFF_WINDOW",
                           "host": host, "attraction": attraction, "ts": ts,
                           "events": [ev]})

    # 4) MISSED_PATCH_WINDOW x4 (deliberately no patch_installed event)
    as_of = extra_windows[-1].end + timedelta(hours=1)
    for idx, w in enumerate(extra_windows):
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "MISSED_PATCH_WINDOW",
                           "host": w.host, "attraction": w.attraction, "ts": w.end,
                           "events": []})

    # 5) CLOCK_DRIFT x4
    for i in range(4):
        attraction = "space-voyager" if i % 2 == 0 else "jungle-trek"
        cfg = ATTRACTIONS[attraction]
        host_list = cfg["control"] + cfg["hmi"]
        host = host_list[i % len(host_list)]
        ts = off_window_time(4 + i, hour=9)
        host_ts = ts - timedelta(seconds=600 + i * 30)  # well over 120s threshold
        ev = f.process(attraction, host, ts, "clock_check", host_ts=host_ts.isoformat() + "Z")
        events.append(ev)
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "CLOCK_DRIFT",
                           "host": host, "attraction": attraction, "ts": ts,
                           "events": [ev]})

    # 6) UNEXPECTED_SERVICE_LOGON x5
    for i in range(5):
        attraction = "space-voyager" if i % 2 == 0 else "jungle-trek"
        cfg = ATTRACTIONS[attraction]
        host = cfg["control"][i % len(cfg["control"])]
        ts = off_window_time(6 + i, hour=13)
        ev = f.winevt(
            attraction, host, ts, 4624, "Security",
            TargetUserName="svc_maint", LogonType=10,
            IpAddress=f"{SUBNET_PREFIX}9.{50 + i}",
        )
        events.append(ev)
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "UNEXPECTED_SERVICE_LOGON",
                           "host": host, "attraction": attraction, "ts": ts,
                           "events": [ev]})

    # 7) CONTROL_HOST_REBOOT_OFF_WINDOW x4
    for i in range(4):
        attraction = "space-voyager" if i % 2 == 0 else "jungle-trek"
        cfg = ATTRACTIONS[attraction]
        host = cfg["control"][i % len(cfg["control"])]
        ts = off_window_time(1 + i, hour=16)
        event_id = 1074 if i % 2 == 0 else 6008
        ev = f.winevt(
            attraction, host, ts, event_id, "System",
            ProcessName="C:\\Windows\\System32\\winlogon.exe",
            Reason="Unscheduled restart",
        )
        events.append(ev)
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "CONTROL_HOST_REBOOT_OFF_WINDOW",
                           "host": host, "attraction": attraction, "ts": ts,
                           "events": [ev]})

    # 8) ISOLATED_HOST_OUTBOUND x5
    for i in range(5):
        attraction = "space-voyager" if i % 2 == 0 else "jungle-trek"
        cfg = ATTRACTIONS[attraction]
        host = cfg["control"][i % len(cfg["control"])]
        ts = off_window_time(8 + i, hour=12)
        ev = f.syslog(
            attraction, "fw-" + attraction, ts, "fw", 2000 + i,
            f"connection accepted src={host} dst=198.51.100.{10 + i} "
            f"dst_port=443 proto=tcp",
            "netconn", src=host, dst=f"198.51.100.{10 + i}",
        )
        events.append(ev)
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "ISOLATED_HOST_OUTBOUND",
                           "host": host, "attraction": attraction, "ts": ts,
                           "events": [ev]})

    # 9) REPEATED_FAILED_AUTH_HMI x4 (each scenario is a burst of 3 lines)
    for i in range(4):
        attraction = "space-voyager" if i % 2 == 0 else "jungle-trek"
        cfg = ATTRACTIONS[attraction]
        host = cfg["hmi"][0]
        base_ts = off_window_time(5 + i, hour=8)
        burst = []
        for j in range(3):
            ts = base_ts + timedelta(minutes=2 * j)
            ev = f.winevt(
                attraction, host, ts, 4625, "Security",
                TargetUserName=f"operator{i}", LogonType=2,
                IpAddress=f"{SUBNET_PREFIX}5.{30 + i}",
            )
            events.append(ev)
            burst.append(ev)
        scenarios.append({"id": f"seed-{sid()}", "rule_id": "REPEATED_FAILED_AUTH_HMI",
                           "host": host, "attraction": attraction, "ts": burst[-1].ts,
                           "events": burst})

    assert len(scenarios) == 40, f"expected 40 seeded scenarios, built {len(scenarios)}"
    events.sort(key=lambda e: e.ts)
    return events, calendar, scenarios, as_of
