import type { MaintenanceWindow } from "../types";

interface Props {
  windows: MaintenanceWindow[];
}

export function CalendarOverlay({ windows }: Props) {
  if (windows.length === 0) {
    return <p data-testid="calendar-empty">No published maintenance windows.</p>;
  }
  const sorted = [...windows].sort((a, b) => a.start.localeCompare(b.start));
  return (
    <ul data-testid="calendar-overlay" className="calendar-overlay">
      {sorted.map((w) => (
        <li key={w.window_id} data-testid="calendar-row">
          <strong>{w.attraction}</strong> / {w.host} : {w.window_type} window {w.start} to{" "}
          {w.end} ({w.ticket})
        </li>
      ))}
    </ul>
  );
}
