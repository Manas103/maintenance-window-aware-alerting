"""Reference (oracle) correlation engine.

Deliberately coded differently from correlation.PrimaryCorrelationEngine:
a classic disjoint-set (union-find) merge instead of BFS over an adjacency
dict, and the fidelity formula re-derived from the alert list by hand
rather than calling correlation.fidelity_score. No helper function is
shared with the primary engine. The two are diffed exactly, incident for
incident, in tests/test_correlation_oracle_diff.py.
"""
from __future__ import annotations

from collections import defaultdict

from .attack import mapping_for
from .models import Incident

_TOTAL_TECHNIQUES = 9
_DIVERSITY_WEIGHT = 40.0
_VOLUME_WEIGHT = 30.0
_VOLUME_CAP = 8
_LATERAL_BONUS = 30.0


class _DisjointSet:
    def __init__(self):
        self._parent = {}

    def find(self, x):
        self._parent.setdefault(x, x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb


def _score(alerts) -> float:
    technique_set = set()
    host_set = set()
    for a in alerts:
        technique_set.add(mapping_for(a.rule_id).technique_id)
        host_set.add(a.host)
    diversity_points = _DIVERSITY_WEIGHT * len(technique_set) / _TOTAL_TECHNIQUES
    capped_count = len(alerts) if len(alerts) < _VOLUME_CAP else _VOLUME_CAP
    volume_points = _VOLUME_WEIGHT * capped_count / _VOLUME_CAP
    lateral_points = _LATERAL_BONUS if len(host_set) >= 2 else 0.0
    total = diversity_points + volume_points + lateral_points
    if total > 100.0:
        total = 100.0
    return round(total, 1)


class ReferenceCorrelationEngine:
    name = "reference-unionfind"

    def group(self, alerts) -> list:
        dsu = _DisjointSet()
        for a in alerts:
            if a.pid is None:
                continue
            dsu.find(a.pid)
            if a.ppid is not None:
                dsu.union(a.pid, a.ppid)

        buckets = defaultdict(list)
        singles = []
        for a in alerts:
            if a.pid is None:
                singles.append(a)
                continue
            root = dsu.find(a.pid)
            buckets[root].append(a)

        incidents = []
        counter = 0
        for group_alerts in buckets.values():
            incidents.append(self._to_incident(f"REF-INC-{counter}", group_alerts))
            counter += 1
        for i, a in enumerate(singles):
            incidents.append(self._to_incident(f"REF-INC-SINGLE-{i}", [a]))

        incidents.sort(key=lambda inc: inc.start_ts)
        return incidents

    def _to_incident(self, incident_id, alerts) -> Incident:
        ordered = sorted(alerts, key=lambda a: a.ts)
        rule_ids = sorted(set(a.rule_id for a in alerts))
        technique_ids = sorted(set(mapping_for(a.rule_id).technique_id for a in alerts))
        hosts = sorted(set(a.host for a in alerts))
        return Incident(
            incident_id=incident_id,
            alert_ids=tuple(a.alert_id for a in ordered),
            rule_ids=tuple(rule_ids),
            technique_ids=tuple(technique_ids),
            hosts=tuple(hosts),
            start_ts=ordered[0].ts,
            end_ts=ordered[-1].ts,
            fidelity_score=_score(alerts),
        )
