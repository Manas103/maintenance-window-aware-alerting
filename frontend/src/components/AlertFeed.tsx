import type { Alert } from "../types";

interface Props {
  alerts: Alert[];
}

export function AlertFeed({ alerts }: Props) {
  if (alerts.length === 0) {
    return <p data-testid="alert-feed-empty">No alerts.</p>;
  }
  return (
    <table data-testid="alert-feed" className="alert-feed">
      <thead>
        <tr>
          <th>Time</th>
          <th>Rule</th>
          <th>Host</th>
          <th>Attraction</th>
          <th>Window state</th>
          <th>Triggering line(s)</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((a) => (
          <tr key={a.alert_id} data-testid="alert-row">
            <td>{a.ts}</td>
            <td>{a.rule_name}</td>
            <td>{a.host}</td>
            <td>{a.attraction}</td>
            <td>{a.window_state}</td>
            <td>
              {a.triggering_lines.map((line, i) => (
                <div className="triggering-line" key={i}>
                  {line}
                </div>
              ))}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
