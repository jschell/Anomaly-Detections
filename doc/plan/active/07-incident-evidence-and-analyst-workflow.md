# Plan 07 — Incident Evidence and Analyst Workflow

## Goal
Provide a controlled path from anomaly finding to investigation and evidence retention.

## Scope
- Keep findings separate from incidents.
- Finding states: unreviewed, investigating, incident, dismissed.
- Explicit incident creation and evidence promotion API.
- Permit full raw-event retention only for activity directly tied to an investigation/incident and selected by analyst action.
- Capture provenance explaining why the retained event set was selected.
- Add evidence lifecycle rules for temporary investigating evidence and dismissed investigations.
- Store analyst labels and notes.
- Provide notebook helpers for pivoting findings back to SIEM query context.

## Exit criteria
A finding can be investigated in the notebook, explicitly promoted into an incident, have selected full events retained with manifest/provenance, and have temporary evidence removed when dismissed according to policy.
