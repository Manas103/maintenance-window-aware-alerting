"""Seeded corpus for the correlation and fidelity-scoring claims.

Separate from `generators.build_seeded_corpus` (the original 40-scenario,
one-alert-per-rule corpus used for the 40/40 detection claim, left
untouched): this corpus is designed to exercise grouping, not detection,
so every event here carries an explicit `pid`/`ppid` attribution (see
models.Alert and correlation.py) that the original corpus's events never
set.

Two kinds of scenario:
  - 15 "chained incidents", each a believable single intrusion narrative
    (an engineering laptop connects off-window, a malicious process starts
    and is the common ancestor of a lateral-movement logon, three
    outbound beacons and an unplanned reboot) that produces 8 alerts
    sharing one process-ancestry tree, so correlation should fold them
    into exactly 1 incident.
  - 18 standalone alerts, each a single unrelated rule firing with its own
    unique, unconnected pid, so correlation must leave each as its own
    incident (the false-grouping check).

This is a design, not a tuned search for 76%: the chain size (8 alerts,
one believable attack progression) and the standalone count (18, a
typical day's worth of one-off findings) were picked for narrative
realism, then measured; see README Findings for the actual number.
"""
from __future__ import annotations

from datetime import timedelta

from .generators import ATTRACTIONS, BASE_DATE, _EventFactory, build_calendar

NUM_CHAINED_INCIDENTS = 15
NUM_STANDALONE = 18

# Every scenario below is scheduled well after this, but evaluating
# MISSED_PATCH_WINDOW "as of" this early timestamp means the one weekly
# patch window build_calendar(num_weeks=1) creates has not closed yet from
# the evaluator's point of view, so it never fires here; this corpus is not
# about that rule at all, and no scenario below supplies a patch_installed
# event for it to (correctly) react to.
CORRELATION_AS_OF = BASE_DATE


def _off_window_time(day_offset, hour):
    # Same convention as generators.build_seeded_corpus: Wednesdays fall
    # outside every patch (Tue 02-04) and general (Sun 01-05) window.
    return BASE_DATE + timedelta(days=day_offset, hours=hour)


def _tag(event, pid, ppid):
    """Attributes a built LogEvent to a process. `LogEvent` is a frozen
    dataclass but `fields` is a plain dict, so mutating it in place (rather
    than passing pid/ppid as **fields at construction time) is what avoids
    colliding with `_EventFactory.syslog`'s own positional `pid` parameter
    (the cosmetic syslog `proc[pid]:` process id), which names the same
    word for an unrelated purpose."""
    event.fields["pid"] = pid
    event.fields["ppid"] = ppid
    return event


def _chained_incident(f: _EventFactory, idx: int, calendar) -> dict:
    attraction = "space-voyager" if idx % 2 == 0 else "jungle-trek"
    cfg = ATTRACTIONS[attraction]
    control_host = cfg["control"][idx % len(cfg["control"])]
    hmi_host = cfg["hmi"][0]
    eng_laptop = cfg["eng_laptop"]
    day = 20 + idx * 2
    base = _off_window_time(day, hour=10)

    base_pid = 1000 + idx * 100
    p0_remote_session = base_pid
    p1_malicious = base_pid + 1
    p2_child = base_pid + 2

    events = []

    # 1. Engineering laptop reaches the controller off-window.
    events.append(_tag(f.syslog(
        attraction, "fw-" + attraction, base, "fw", p0_remote_session,
        f"connection accepted src={eng_laptop} dst={control_host} dst_port=502 proto=tcp",
        "netconn", src=eng_laptop, dst=control_host,
    ), p0_remote_session, None))

    # 2. A malicious process starts on the control host, attributed as a
    # consequence of that remote session.
    bad_hash = f"deadbeef-chain-{idx}"
    events.append(_tag(f.process(
        attraction, control_host, base + timedelta(minutes=2), "process_start",
        path="C:\\Windows\\Temp\\svc_update.exe", sha256=bad_hash, user="SYSTEM",
    ), p1_malicious, p0_remote_session))

    # 3. Lateral movement: an unexpected service logon, attributed to a
    # child of the malicious process.
    events.append(_tag(f.winevt(
        attraction, control_host, base + timedelta(minutes=5), 4624, "Security",
        TargetUserName="svc_maint", LogonType=10, IpAddress="203.0.113.50",
    ), p2_child, p1_malicious))

    # 4-6. Three outbound beacons from the same child process.
    for b in range(3):
        events.append(_tag(f.syslog(
            attraction, "fw-" + attraction, base + timedelta(minutes=10 + 5 * b), "fw",
            p2_child,
            f"connection accepted src={control_host} dst=198.51.100.{30 + idx} dst_port=443 proto=tcp",
            "netconn", src=control_host, dst=f"198.51.100.{30 + idx}",
        ), p2_child, p1_malicious))

    # 7. Repeated failed HMI auth (3 lines, one alert), same child process.
    for j in range(3):
        events.append(_tag(f.winevt(
            attraction, hmi_host, base + timedelta(minutes=30 + 2 * j), 4625, "Security",
            TargetUserName=f"operator{idx}", LogonType=2, IpAddress="203.0.113.50",
        ), p2_child, p1_malicious))

    # 8. Impact: the control host reboots unexpectedly, attributed to the
    # malicious process directly.
    events.append(_tag(f.winevt(
        attraction, control_host, base + timedelta(minutes=45), 6008, "System",
        ProcessName="C:\\Windows\\System32\\winlogon.exe", Reason="Unscheduled restart",
    ), p1_malicious, p0_remote_session))

    return {
        "incident_idx": idx,
        "events": events,
        "expected_rule_ids": {
            "ENG_LAPTOP_OFF_WINDOW", "NEW_EXEC_CONTROL_HOST", "UNEXPECTED_SERVICE_LOGON",
            "ISOLATED_HOST_OUTBOUND", "REPEATED_FAILED_AUTH_HMI", "CONTROL_HOST_REBOOT_OFF_WINDOW",
        },
        "expected_alert_count": 8,
        "hosts": {control_host, hmi_host},
    }


_STANDALONE_BUILDERS = []


def _standalone_new_exec(f, idx, attraction, cfg):
    host = cfg["control"][0]
    ts = _off_window_time(60 + idx, hour=9)
    return _tag(f.process(
        attraction, host, ts, "process_start",
        path="C:\\Windows\\Temp\\onceoff.exe", sha256=f"standalone-hash-{idx}", user="SYSTEM",
    ), 9000 + idx, None)


def _standalone_removable_media(f, idx, attraction, cfg):
    host = cfg["backstage"][0]
    ts = _off_window_time(60 + idx, hour=9)
    return _tag(f.winevt(
        attraction, host, ts, 6416, "System",
        DeviceDescription="USB Mass Storage Device", ClassName="DiskDrive",
    ), 9000 + idx, None)


def _standalone_clock_drift(f, idx, attraction, cfg):
    host = cfg["control"][0]
    ts = _off_window_time(60 + idx, hour=9)
    host_ts = ts - timedelta(seconds=900)
    return _tag(f.process(
        attraction, host, ts, "clock_check", host_ts=host_ts.isoformat() + "Z",
    ), 9000 + idx, None)


def _standalone_reboot(f, idx, attraction, cfg):
    host = cfg["control"][0]
    ts = _off_window_time(60 + idx, hour=9)
    return _tag(f.winevt(
        attraction, host, ts, 1074, "System",
        ProcessName="C:\\Windows\\System32\\winlogon.exe", Reason="Unscheduled restart",
    ), 9000 + idx, None)


_STANDALONE_BUILDERS = [
    _standalone_new_exec,
    _standalone_removable_media,
    _standalone_clock_drift,
    _standalone_reboot,
]


def _standalone_alert(f: _EventFactory, idx: int) -> dict:
    attraction = "space-voyager" if idx % 2 == 0 else "jungle-trek"
    cfg = ATTRACTIONS[attraction]
    builder = _STANDALONE_BUILDERS[idx % len(_STANDALONE_BUILDERS)]
    ev = builder(f, idx, attraction, cfg)
    return {"standalone_idx": idx, "events": [ev]}


def build_correlation_corpus():
    """Returns (events, calendar, chained_incidents, standalone) where
    chained_incidents and standalone are the ground-truth fixture
    descriptions used by the tests, not inferred from the engine output."""
    f = _EventFactory()
    calendar = build_calendar(num_weeks=1)

    chained_incidents = [_chained_incident(f, i, calendar) for i in range(NUM_CHAINED_INCIDENTS)]
    standalone = [_standalone_alert(f, i) for i in range(NUM_STANDALONE)]

    events = []
    for inc in chained_incidents:
        events.extend(inc["events"])
    for s in standalone:
        events.extend(s["events"])
    events.sort(key=lambda e: e.ts)

    assert len(chained_incidents) == NUM_CHAINED_INCIDENTS
    assert len(standalone) == NUM_STANDALONE

    return events, calendar, chained_incidents, standalone
