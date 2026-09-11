"""Claim: sources are simulated Windows event logs, Linux syslog and
endpoint process telemetry."""
import json

from app.generators import build_clean_corpus


def test_three_source_types_present_and_shaped_correctly():
    events, _calendar = build_clean_corpus(num_days=10)
    sources = {e.source for e in events}
    assert sources == {"winevt", "syslog", "process"}

    winevt = next(e for e in events if e.source == "winevt")
    payload = json.loads(winevt.raw)
    assert "EventID" in payload and "Computer" in payload and "TimeCreated" in payload

    syslog = next(e for e in events if e.source == "syslog")
    assert syslog.raw[:3] in {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    }
    assert "[" in syslog.raw and "]:" in syslog.raw

    process = next(e for e in events if e.source == "process")
    payload = json.loads(process.raw)
    assert "host" in payload and "event" in payload and "ts" in payload
