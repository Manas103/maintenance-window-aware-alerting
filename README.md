# Control System Monitoring Dashboard with Maintenance-Window-Aware Alerting

A detection engine that scores nine named rules over simulated Windows
event log, Linux syslog and endpoint process-telemetry sources against a
published maintenance calendar, so the identical event type is not an
incident inside a scheduled window and is one outside it, served by a
FastAPI backend and rendered by a React/TypeScript dashboard. Stack:
Python, FastAPI, SQLAlchemy, React, TypeScript, PostgreSQL-shaped schema
(SQLite locally), Grafana. Every number below was measured on this
machine, not targeted.

## Why this exists

This is a small version of the "monitoring and logging" sub-team's core
problem on an Attractions Operational Technology floor: the same log line
(a new executable, a USB device, an engineering laptop reaching a
controller) means nothing during a published four-hour maintenance window
and means an incident five minutes after it closes. A detector that cannot
tell those two situations apart either misses real incidents during
maintenance or pages someone every single patch night. This project builds
the calendar-aware scoring that makes that distinction for real, against
two independently coded implementations that have to agree exactly.

## Honest framing, up front

- **Every log source is synthetic and disclosed as such.** `generators.py`
  builds Windows Security/System event log JSON (shaped like
  `Get-WinEvent | ConvertTo-Json` output), RFC 3164-style Linux syslog
  lines, and endpoint process-telemetry JSON for two fictional attractions
  and their control hosts, HMIs and engineering laptops. No real Disney,
  vendor, or attraction system was observed or reproduced.
- **PostgreSQL was not stood up as a running service on this build
  machine.** The schema (`db.py`) is written to be Postgres-compatible
  (plain column types, no SQLite-only features) and the exact stand-up
  command is documented below; every test and API call in this repo runs
  for real against local SQLite instead. If `POSTGRES_URL` is set and
  reachable, the app and `tests/test_api.py::test_against_real_postgres`
  use real Postgres and the test stops skipping; it currently skips
  cleanly (`docs/test_output.txt`), disclosed rather than hidden.
- **Grafana itself was not stood up either.** `grafana/dashboard.json` is a
  real, valid Grafana dashboard definition (bar gauge, pie chart, alert
  table and calendar table panels, each a real SQL query against the
  schema above) that imports into a running Grafana pointed at this
  project's Postgres instance; it was authored and JSON-validated, not
  rendered against a live Grafana server.
- **The frontend is a data console, not a themed UI.** `App.tsx` fetches
  `/alerts`, `/rules` and `/calendar` and renders three plain tables; there
  is no styling investment beyond making the data legible.
- Machine: 8 physical / 16 logical cores, Windows 11, Python 3.12.10,
  FastAPI 0.115.6, SQLAlchemy 2.0.36, pandas 2.2.3, Node 22.17.1, React
  19.2.8, Vite 8.3.0, Vitest 2.1.9.

## Architecture

```
backend/app/
  models.py             LogEvent, MaintenanceWindow, Alert, RuleDef dataclasses
  generators.py           synthetic Windows event log / syslog / process-telemetry sources + maintenance calendar (two attractions)
  rules.py                    the nine named RuleDef rows (id, name, description, window_aware)
  engine.py                    primary detector: pandas-indexed, evaluates all nine rules against events + calendar
  reference_engine.py    independent oracle: a plain-loop implementation, no pandas, no shared helpers with engine.py
  db.py                        SQLAlchemy schema (Postgres-shaped, SQLite by default), stand-up command for real Postgres
  main.py                     FastAPI app: /health, /rules, /calendar, /alerts
  seed_db.py                  loads generators.py output through engine.py into the configured database
backend/tests/
  test_sources.py               shape checks for the three source types
  test_rules_and_calendar.py  exactly 9 rules, the 5 named categories present, calendar scores every attraction/host
  test_seeded_events.py       40/40 seeded events alert, naming the rule and the triggering line(s)
  test_clean_days.py            0/40 false alerts across 40 clean operating days
  test_oracle_diff.py           primary vs. reference_engine.py, exact agreement over the seeded corpus and the clean days
  test_api.py                     FastAPI endpoint tests; test_against_real_postgres skips cleanly if POSTGRES_URL is unset/unreachable
frontend/src/
  App.tsx                        fetches /alerts, /rules, /calendar; renders AlertFeed + CalendarOverlay
  components/AlertFeed.tsx    table: time, rule, host, attraction, window state, triggering line(s)
  components/CalendarOverlay.tsx    table of published maintenance windows
frontend/tests/               Vitest + Testing Library, jsdom environment
grafana/dashboard.json      4-panel Grafana dashboard against the schema in db.py (see Honest framing)
```

### Design deep-dives

**Two engines, deliberately different implementations.** `engine.py`
indexes every event into a pandas DataFrame and evaluates all nine rules
vectorized against it; `reference_engine.py` never imports pandas, it is a
plain nested-loop oracle with no helper function shared with the primary
engine. The two are diffed exactly in `test_oracle_diff.py` over both the
40-event seeded corpus and the 40 clean days, so an alert-set agreement is
a real cross-check, not two paths through the same bug.

**Window-awareness is a per-rule property, not a global switch.** Of the
five rule categories the resume bullet names explicitly, three are
suppressed inside a published window (`window_aware=True`): new executable
on a control host, removable media backstage, and engineering laptop
reaching a controller off-window, because a deployment, a USB patch
transfer, or an engineer's laptop connecting are all expected during
maintenance and only mean something outside it. The other two named
categories are deliberately `window_aware=False`, never suppressed, because
each one's own definition is already calendar-relative rather than a raw
event the calendar should excuse: missed patch window fires exactly when a
published window closed without the patch it was for, so there is no
"inside the window" case to suppress, and clock drift is never excused
because a drifted clock poisons every other timestamp-based control on
that host, maintenance day or not. The four rules beyond the named five
split the same way: unexpected service logon and control host reboot are
`window_aware=True` (both are routine during a maintenance visit);
isolated-host outbound traffic and repeated failed HMI authentication are
`window_aware=False` (isolation is not relaxed for maintenance, and a
credential-guessing attempt is not excused by one). Every alert still
records `window_state` regardless of whether its rule is suppressible, so
a non-suppressed rule's alerts remain visibly scored against the calendar.

**`missed_patch_window` is evaluated once per closed window, not once per
event.** Every other rule reacts to an event that arrived; this one reacts
to an event that did not, a `patch_installed` telemetry line that should
have appeared before a published patch-type window closed and never did.
That asymmetry is why it is `window_aware=False` in the rule table but is
still fundamentally about the calendar: its trigger condition is defined
entirely in calendar terms, not suppressed by one.

## Validation

Backend: `docs/test_output.txt`

```
12 passed, 1 skipped in 0.85s
```

(the 1 skip is `test_against_real_postgres`, skipped cleanly because
`POSTGRES_URL` is unset on this machine; see Honest framing.)

Primary vs. reference-engine oracle diff: `docs/oracle_diff.txt`

```
== seeded corpus (40 scenarios + 14 clean baseline days) ==
primary alerts: 40   reference alerts: 40   only in primary: 0   only in reference: 0
EXACT AGREEMENT: True

== 40 clean operating days ==
primary alerts: 0    reference alerts: 0    only in primary: 0   only in reference: 0
EXACT AGREEMENT: True
```

Seeded-events detail, one block per scenario naming the rule and quoting
every triggering log line: `docs/seeded_events_output.txt`.

Frontend: `docs/frontend_test_output.txt`

```
Test Files  2 passed (2)
     Tests  4 passed (4)
```

## Findings

**The frontend test suite initially failed with `ReferenceError: React is
not defined` on every test that rendered a component, despite
`tsconfig.json` already setting `"jsx": "react-jsx"` (the automatic
runtime that should not need `React` in scope at all).** The wrong
hypothesis was a missing `import React from "react"` in the test files;
adding it would have masked the real problem rather than fixed it, since
`AlertFeed.tsx` and `App.tsx` themselves have no such import and are not
what failed. The measurement that discriminated: the production Vite dev
server path (not exercised by this repo's tests, since there is no
Playwright e2e run in this build) uses the same `@vitejs/plugin-react`
plugin, but Vitest 2.1.9 under Vite 8.3.0, a newer major than Vitest 2.x
is built against, was not applying that plugin's JSX transform inside its
own esbuild-based test transform pipeline, falling back to esbuild's
classic-runtime default instead of honoring `tsconfig.json`. Root cause:
a version-skew gap between Vitest's bundled transform and the installed
Vite major. Fix: `vite.config.ts` now sets `esbuild: { jsx: "automatic" }`
explicitly, so the test transform pipeline uses the automatic runtime
regardless of what the plugin pipeline would otherwise have inferred from
`tsconfig.json`.

**Fixing that surfaced two ordinary Testing Library query-ambiguity
failures, not new bugs.** `App.test.tsx` queried
`screen.getByText("New executable on a control host")` and
`screen.getByText(/CTRL-SPACEVOY-01/)` unscoped; both strings legitimately
appear twice in the rendered page (the rule name in both the alert feed
and a rules panel; the host in both the Host column and the triggering
JSON line's own `"Computer"` field), so `getByText` correctly threw on
multiple matches. Fix: both assertions were scoped with
`within(alertFeed)` and, for the host string, changed to `getAllByText`
against the specific alert row, which is what the test actually meant to
assert.

## Measured results

Machine: 8 physical / 16 logical cores, Windows 11, Python 3.12.10,
Node 22.17.1. Raw output: `docs/test_output.txt`, `docs/oracle_diff.txt`,
`docs/seeded_events_output.txt`, `docs/frontend_test_output.txt`.

| Metric | Measured | Claimed |
|---|---|---|
| Seeded events alerted, naming the rule and triggering line(s) | **40 / 40** | 40 / 40 |
| False alerts across 40 clean operating days | **0 / 40** | 0 / 40 |
| Primary vs. reference-engine agreement (seeded + clean corpora) | **exact** | exact |
| Named detection rules | **9** | 9 |
| Rules scored against the published maintenance calendar | **9 / 9** | 9 |
| Backend tests | **12 passed, 1 skipped** (Postgres unreachable) | n/a |
| Frontend tests | **4 / 4 passed** | n/a |

All claims were met on the first genuine attempt once the two disclosed
version/query issues above were fixed during development (see Findings);
no number here was tuned to hit a target.

## Building and running

```
# Backend
cd backend
python -m venv ../venv
../venv/Scripts/python.exe -m pip install -r ../requirements.txt
../venv/Scripts/python.exe -m pytest -q                        # 12 passed, 1 skipped
../venv/Scripts/python.exe -m uvicorn app.main:app --port 0    # pick a free port; never a fixed busy one

# Against real PostgreSQL instead of local SQLite:
docker run --name mwaa-postgres -e POSTGRES_PASSWORD=mwaa -e POSTGRES_DB=mwaa -p 5432:5432 -d postgres:16
export POSTGRES_URL=postgresql+psycopg2://postgres:mwaa@localhost:5432/mwaa

# Frontend
cd frontend
npm install
npm run test    # 4 passed
npm run dev      # PORT env var overrides the default 5173

# Grafana: import grafana/dashboard.json into a Grafana instance pointed at POSTGRES_URL
```

## Sibling comparison

Against the portfolio, three repos share pieces of this domain but not the
whole shape. [`telemetry-ground-station`](https://github.com/Manas103/telemetry-ground-station)
has a real fault classifier, a Prometheus exporter and an oracle diff, but
in a spacecraft-telemetry domain with no security semantics and no
calendar. [`it-service-level-change-risk-console`](https://github.com/Manas103/it-service-level-change-risk-console)
has an SLA-breach engine, a console and an oracle diff, but ITIL service
management is enterprise IT, which is precisely the framing this project
is built to avoid. [`device-telemetry-policy-middleware`](https://github.com/Manas103/device-telemetry-policy-middleware)
has a live-enforced policy plane, closer in spirit, wrong in domain. None
of the three score a detection rule against a published maintenance
calendar, which is the mechanism this project's headline claim depends on.

## Limitations

- Every log source, host, attraction and the maintenance calendar itself
  are synthetic; no real Disney, vendor, or attraction system was observed.
- PostgreSQL and Grafana were not stood up as running services on this
  build machine; both are exercised against a real, schema-compatible
  substitute (SQLite for Postgres, a JSON-validated but unrendered
  dashboard for Grafana) and the stand-up commands are documented above,
  not run unattended on a shared machine.
- The nine rules cover the five categories the resume bullet names
  explicitly plus four more designed to round out the set; they are not an
  exhaustive catalog of every detection an attraction floor would need.
- `missed_patch_window` is evaluated once per closed window; a patch
  installed after the window closed but before the next evaluation run is
  still reported as missed, since this project has no continuously running
  scheduler, only a batch evaluation over a fixed event corpus.
