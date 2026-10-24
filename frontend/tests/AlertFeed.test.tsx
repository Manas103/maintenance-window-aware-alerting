import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AlertFeed } from "../src/components/AlertFeed";

describe("AlertFeed", () => {
  it("renders an empty state with no alerts", () => {
    render(<AlertFeed alerts={[]} />);
    expect(screen.getByTestId("alert-feed-empty")).toBeInTheDocument();
  });

  it("renders one row per alert with the rule name and triggering line", () => {
    render(
      <AlertFeed
        alerts={[
          {
            alert_id: "a1",
            rule_id: "CLOCK_DRIFT",
            rule_name: "Clock drift",
            host: "CTRL-SPACEVOY-01",
            attraction: "space-voyager",
            ts: "2026-06-05T09:00:00",
            triggering_lines: ['{"event": "clock_check"}'],
            explanation: "drift",
            window_state: "out_of_window",
            technique_id: "T1070.006",
            technique_name: "Indicator Removal: Timestomp",
            pid: null,
            ppid: null,
          },
        ]}
      />,
    );
    expect(screen.getAllByTestId("alert-row")).toHaveLength(1);
    expect(screen.getByText("Clock drift")).toBeInTheDocument();
    expect(screen.getByText('{"event": "clock_check"}')).toBeInTheDocument();
  });
});
