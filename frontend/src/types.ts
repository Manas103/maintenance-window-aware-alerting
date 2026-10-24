export interface Alert {
  alert_id: string;
  rule_id: string;
  rule_name: string;
  host: string;
  attraction: string;
  ts: string;
  triggering_lines: string[];
  explanation: string;
  window_state: string;
  technique_id: string;
  technique_name: string;
  pid: number | null;
  ppid: number | null;
}

export interface Incident {
  incident_id: string;
  alert_ids: string[];
  rule_ids: string[];
  technique_ids: string[];
  hosts: string[];
  start_ts: string;
  end_ts: string;
  alert_count: number;
  fidelity_score: number;
}

export interface IncidentsResponse {
  incidents: Incident[];
  reduction: {
    alerts_before: number;
    incidents_after: number;
    reduction_pct: number;
  };
}

export interface Rule {
  rule_id: string;
  name: string;
  description: string;
  window_aware: boolean;
}

export interface MaintenanceWindow {
  window_id: string;
  attraction: string;
  host: string;
  start: string;
  end: string;
  window_type: string;
  ticket: string;
  description: string;
}
