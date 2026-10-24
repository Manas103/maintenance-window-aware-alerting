import { render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../src/App";

const mockAlert = {
  alert_id: "NEW_EXEC_CONTROL_HOST|CTRL-SPACEVOY-01|2026-06-10T10:00:00",
  rule_id: "NEW_EXEC_CONTROL_HOST",
  rule_name: "New executable on a control host",
  host: "CTRL-SPACEVOY-01",
  attraction: "space-voyager",
  ts: "2026-06-10T10:00:00",
  triggering_lines: ['{"EventID": 1, "Computer": "CTRL-SPACEVOY-01"}'],
  explanation: "test",
  window_state: "out_of_window",
  technique_id: "T1204.002",
  technique_name: "User Execution: Malicious File",
  pid: null,
  ppid: null,
};

const mockIncidents = {
  incidents: [
    {
      incident_id: "INC-0",
      alert_ids: [mockAlert.alert_id],
      rule_ids: [mockAlert.rule_id],
      technique_ids: [mockAlert.technique_id],
      hosts: [mockAlert.host],
      start_ts: mockAlert.ts,
      end_ts: mockAlert.ts,
      alert_count: 1,
      fidelity_score: 8.2,
    },
  ],
  reduction: { alerts_before: 1, incidents_after: 1, reduction_pct: 0.0 },
};

const mockRule = {
  rule_id: "NEW_EXEC_CONTROL_HOST",
  name: "New executable on a control host",
  description: "test rule",
  window_aware: true,
};

const mockWindow = {
  window_id: "MW-1",
  attraction: "space-voyager",
  host: "CTRL-SPACEVOY-01",
  start: "2026-06-09T02:00:00",
  end: "2026-06-09T04:00:00",
  window_type: "patch",
  ticket: "MW-SPACEVOY-0001",
  description: "Weekly patch window",
};

describe("App", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.includes("/alerts")) {
          return Promise.resolve({ ok: true, json: () => Promise.resolve([mockAlert]) } as Response);
        }
        if (url.includes("/rules")) {
          return Promise.resolve({ ok: true, json: () => Promise.resolve([mockRule]) } as Response);
        }
        if (url.includes("/calendar")) {
          return Promise.resolve({ ok: true, json: () => Promise.resolve([mockWindow]) } as Response);
        }
        if (url.includes("/incidents")) {
          return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIncidents) } as Response);
        }
        return Promise.reject(new Error("unexpected url " + url));
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the alert feed, rules and calendar once the API responds", async () => {
    render(<App />);

    await waitFor(() => expect(screen.getByTestId("alert-feed")).toBeInTheDocument());

    const alertFeed = screen.getByTestId("alert-feed");
    expect(within(alertFeed).getByText("New executable on a control host", { exact: false })).toBeInTheDocument();
    const alertRows = screen.getAllByTestId("alert-row");
    expect(alertRows).toHaveLength(1);
    expect(within(alertRows[0]).getAllByText(/CTRL-SPACEVOY-01/).length).toBeGreaterThan(0);
    expect(screen.getByTestId("calendar-overlay")).toBeInTheDocument();
    expect(screen.getAllByTestId("calendar-row")).toHaveLength(1);
    expect(screen.getByText(/MW-SPACEVOY-0001/)).toBeInTheDocument();
  });

  it("shows an error state when the API is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("connection refused"))),
    );
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("app-error")).toBeInTheDocument());
  });
});
