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
