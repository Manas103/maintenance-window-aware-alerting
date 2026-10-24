"""Primary correlation engine: groups alerts sharing a process-ancestry
chain into one fidelity-scored incident.

Two alerts are in the same incident when their pid nodes are connected
through ppid edges, computed as connected components of a real graph, not
a shared label. `pid` here is the attribution id an EDR/SOAR correlation
layer would already have resolved (e.g. a process GUID), global rather
than scoped per host: that is what lets an alert recorded against one host
(a failed HMI logon) still chain to a causing process that another alert
recorded against a different host (the control host it actually ran on).
Keying the graph by (host, pid) instead was tried first and is exactly the
bug this repo's Findings section documents: a cross-host step in a chain
silently split into its own singleton incident because its pid collided
with nothing on its own host. An alert with no pid (MISSED_PATCH_WINDOW
has none; nothing causes it) is always its own one-alert incident.

This is one of two independently coded implementations; see
reference_correlation.py for the union-find oracle used in
tests/test_correlation_oracle_diff.py, exactly the same pattern engine.py
and reference_engine.py already use for detection.
"""
from __future__ import annotations

from collections import defaultdict

from .attack import mapping_for
from .models import Incident

TOTAL_TECHNIQUES = 9  # len(ATTACK_MAPPING); every rule maps to one technique
DIVERSITY_WEIGHT = 40.0
VOLUME_WEIGHT = 30.0
VOLUME_CAP_ALERTS = 8
LATERAL_WEIGHT = 30.0


def fidelity_score(alerts) -> float:
    """0..100. Rewards technique diversity (40 pts, scaled to how many of
    the 9 possible ATT&CK techniques appear), alert volume (30 pts,
    capped at VOLUME_CAP_ALERTS so a single noisy rule can't dominate),
    and a flat 30-point bonus for spanning more than one host (lateral
    movement). Deterministic and inspectable on purpose: an analyst can
    recompute it from the incident's own alert list by hand."""
    distinct_techniques = {mapping_for(a.rule_id).technique_id for a in alerts}
    distinct_hosts = {a.host for a in alerts}
    diversity = DIVERSITY_WEIGHT * (len(distinct_techniques) / TOTAL_TECHNIQUES)
    volume = VOLUME_WEIGHT * min(1.0, len(alerts) / VOLUME_CAP_ALERTS)
    lateral = LATERAL_WEIGHT if len(distinct_hosts) > 1 else 0.0
    return round(min(100.0, diversity + volume + lateral), 1)


class PrimaryCorrelationEngine:
    name = "primary-bfs"

    def group(self, alerts) -> list:
        """Returns a list of Incident, one per connected component (or one
        per pid-less alert)."""
        with_pid = [a for a in alerts if a.pid is not None]
        without_pid = [a for a in alerts if a.pid is None]

        adjacency = defaultdict(set)
        nodes = set()
        for a in with_pid:
            nodes.add(a.pid)
            adjacency.setdefault(a.pid, set())
            if a.ppid is not None:
                nodes.add(a.ppid)
                adjacency[a.pid].add(a.ppid)
                adjacency[a.ppid].add(a.pid)

        visited = set()
        component_of = {}
        next_component_id = 0
        for start in nodes:
            if start in visited:
                continue
            stack = [start]
            while stack:
                cur = stack.pop()
                if cur in visited:
                    continue
                visited.add(cur)
                component_of[cur] = next_component_id
                for neighbor in adjacency[cur]:
                    if neighbor not in visited:
                        stack.append(neighbor)
            next_component_id += 1

        alerts_by_component = defaultdict(list)
        for a in with_pid:
            cid = component_of[a.pid]
            alerts_by_component[cid].append(a)

        incidents = []
        for cid, group_alerts in alerts_by_component.items():
            incidents.append(_build_incident(f"INC-{cid}", group_alerts))
        for i, a in enumerate(without_pid):
            incidents.append(_build_incident(f"INC-SINGLE-{i}", [a]))

        incidents.sort(key=lambda inc: inc.start_ts)
        return incidents


def _build_incident(incident_id, alerts) -> Incident:
    alerts_sorted = sorted(alerts, key=lambda a: a.ts)
    return Incident(
        incident_id=incident_id,
        alert_ids=tuple(a.alert_id for a in alerts_sorted),
        rule_ids=tuple(sorted({a.rule_id for a in alerts})),
        technique_ids=tuple(sorted({mapping_for(a.rule_id).technique_id for a in alerts})),
        hosts=tuple(sorted({a.host for a in alerts})),
        start_ts=alerts_sorted[0].ts,
        end_ts=alerts_sorted[-1].ts,
        fidelity_score=fidelity_score(alerts),
    )


def incident_to_dict(incident) -> dict:
    return {
        "incident_id": incident.incident_id,
        "alert_ids": list(incident.alert_ids),
        "rule_ids": list(incident.rule_ids),
        "technique_ids": list(incident.technique_ids),
        "hosts": list(incident.hosts),
        "start_ts": incident.start_ts.isoformat(),
        "end_ts": incident.end_ts.isoformat(),
        "alert_count": incident.alert_count(),
        "fidelity_score": incident.fidelity_score,
    }


def analyst_facing_reduction(alerts) -> dict:
    """The 76% claim: how many fewer items an analyst has to triage after
    correlation than before it."""
    incidents = PrimaryCorrelationEngine().group(alerts)
    before = len(alerts)
    after = len(incidents)
    reduction_pct = 0.0 if before == 0 else round(100.0 * (1 - after / before), 1)
    return {
        "alerts_before": before,
        "incidents_after": after,
        "reduction_pct": reduction_pct,
    }
