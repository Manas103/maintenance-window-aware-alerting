import type { IncidentsResponse } from "../types";

interface Props {
  data: IncidentsResponse | null;
}

export function IncidentPanel({ data }: Props) {
  if (!data) {
    return <p data-testid="incident-panel-empty">No incidents.</p>;
  }
  const { incidents, reduction } = data;
  const sorted = [...incidents].sort((a, b) => b.fidelity_score - a.fidelity_score);
  return (
    <div>
      <p data-testid="incident-reduction">
        {reduction.alerts_before} alerts correlated into {reduction.incidents_after} incidents
        ({reduction.reduction_pct}% fewer analyst-facing items).
      </p>
      <table data-testid="incident-panel" className="incident-panel">
        <thead>
          <tr>
            <th>Incident</th>
            <th>Alerts</th>
            <th>Rules</th>
            <th>ATT&amp;CK techniques</th>
            <th>Hosts</th>
            <th>Fidelity</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((inc) => (
            <tr key={inc.incident_id} data-testid="incident-row">
              <td>{inc.incident_id}</td>
              <td>{inc.alert_count}</td>
              <td>{inc.rule_ids.join(", ")}</td>
              <td>{inc.technique_ids.join(", ")}</td>
              <td>{inc.hosts.join(", ")}</td>
              <td>{inc.fidelity_score}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
