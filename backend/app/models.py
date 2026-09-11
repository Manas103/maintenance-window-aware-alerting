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

    def key(self):
        """A content key used to diff two alert sets for exact agreement."""
        return (
            self.rule_id,
            self.host,
            self.attraction,
            self.ts.isoformat(),
            tuple(sorted(self.triggering_lines)),
        )
