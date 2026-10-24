"""Shared data shapes for the detection engine.

These are plain dataclasses, not ORM models (see db.py for the persistence
layer used by the FastAPI service). Keeping the engine's working types free
of any database or web framework import is what lets the reference engine
be built with zero shared code against the primary engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class LogEvent:
    """One line of synthetic log data from one of the three sources."""

    event_id: str
    source: str  # "winevt" | "syslog" | "process"
    host: str
    attraction: str
    ts: datetime
    raw: str  # the exact text as it would appear in the source log
    kind: str  # normalized event kind, e.g. "logon_failed", "process_start"
    fields: dict = field(default_factory=dict)


@dataclass(frozen=True)
class MaintenanceWindow:
    """One published maintenance window for one attraction/host pair."""

    window_id: str
    attraction: str
    host: str  # "*" means every control host at the attraction
    start: datetime
    end: datetime
    window_type: str  # "patch" | "general"
    ticket: str
    description: str


@dataclass(frozen=True)
class RuleDef:
    rule_id: str
    name: str
    description: str
    window_aware: bool  # True if the rule is suppressed inside a matching window


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    host: str
    attraction: str
    ts: datetime
    triggering_lines: tuple
    explanation: str
    window_state: str  # "in_window" | "out_of_window" | "not_applicable"
    # Process-ancestry attribution, carried through from the triggering
    # event's own fields when present (None for alerts with no process to
    # attribute, e.g. MISSED_PATCH_WINDOW). See correlation.py: two alerts
    # are grouped into one incident when their (host, pid) nodes are
    # connected through ppid edges, not by a shared label.
    pid: Optional[int] = None
    ppid: Optional[int] = None

    def key(self):
        """A content key used to diff two alert sets for exact agreement."""
        return (
            self.rule_id,
            self.host,
            self.attraction,
            self.ts.isoformat(),
            tuple(sorted(self.triggering_lines)),
            self.pid,
            self.ppid,
        )


@dataclass(frozen=True)
class Incident:
    """One connected component of the process-ancestry graph over a set of
    alerts, scored for analyst triage priority."""

    incident_id: str
    alert_ids: tuple
    rule_ids: tuple  # distinct rule ids present, sorted
    technique_ids: tuple  # distinct ATT&CK technique ids present, sorted
    hosts: tuple  # distinct hosts present, sorted
    start_ts: datetime
    end_ts: datetime
    fidelity_score: float  # 0..100, see correlation.py for the formula

    def alert_count(self) -> int:
        return len(self.alert_ids)

    def content_key(self):
        """A content key used to diff two incident sets for exact
        agreement, ignoring the generated incident_id (the two engines
        name incidents differently)."""
        return (
            tuple(sorted(self.alert_ids)),
            self.rule_ids,
            self.technique_ids,
            self.hosts,
            self.fidelity_score,
        )
