import type { Alert, IncidentsResponse, MaintenanceWindow, Rule } from "./types";

const API_BASE = (import.meta as any).env?.VITE_API_URL ?? "http://localhost:8000";

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    throw new Error(`${path} responded ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export function fetchAlerts(): Promise<Alert[]> {
  return getJson<Alert[]>("/alerts?limit=500");
}

export function fetchRules(): Promise<Rule[]> {
  return getJson<Rule[]>("/rules");
}

export function fetchCalendar(): Promise<MaintenanceWindow[]> {
  return getJson<MaintenanceWindow[]>("/calendar");
}

export function fetchIncidents(): Promise<IncidentsResponse> {
  return getJson<IncidentsResponse>("/incidents");
}
