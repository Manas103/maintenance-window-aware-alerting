import { useEffect, useState } from "react";
import { fetchAlerts, fetchCalendar, fetchIncidents, fetchRules } from "./api";
import { AlertFeed } from "./components/AlertFeed";
import { CalendarOverlay } from "./components/CalendarOverlay";
import { IncidentPanel } from "./components/IncidentPanel";
import type { Alert, IncidentsResponse, MaintenanceWindow, Rule } from "./types";

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [windows, setWindows] = useState<MaintenanceWindow[]>([]);
  const [incidents, setIncidents] = useState<IncidentsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([fetchAlerts(), fetchRules(), fetchCalendar(), fetchIncidents()])
      .then(([a, r, w, i]) => {
        setAlerts(a);
        setRules(r);
        setWindows(w);
        setIncidents(i);
      })
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <main>
      <h1>Control System Monitoring Dashboard</h1>
      <p>Maintenance-window-aware alerting over simulated attraction control networks.</p>
      {error && <p data-testid="app-error">Could not reach the API: {error}</p>}

      <section>
        <h2>Rules ({rules.length})</h2>
        <ul data-testid="rules-list">
          {rules.map((r) => (
            <li key={r.rule_id}>
              <strong>{r.name}</strong> {r.window_aware ? "(window-aware)" : "(always active)"}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Maintenance calendar</h2>
        <CalendarOverlay windows={windows} />
      </section>

      <section>
        <h2>Incidents (process-ancestry correlation)</h2>
        <IncidentPanel data={incidents} />
      </section>

      <section>
        <h2>Alert feed ({alerts.length})</h2>
        <AlertFeed alerts={alerts} />
      </section>
    </main>
  );
}
