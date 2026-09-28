# Plan 07 — Incident Evidence and Analyst Workflow

## Goal
Provide a controlled path from anomaly finding to investigation and evidence retention.

## Completed
Implemented and validated:
- findings remain distinct from investigation/incident records
- finding workflow states: investigating, incident, dismissed
- explicit investigation creation
- analyst notes
- SIEM query-context helper via the original finding
- explicit analyst-selected evidence retention
- evidence manifests recording finding, investigation/incident IDs, selection reason, timestamp, filename, and row count
- temporary investigation evidence under `investigations/`
- explicit promotion from investigation to confirmed incident
- promotion moves retained evidence into `incidents/<incident-id>/`
- dismissal removes temporary full-event evidence
- dismissed disposition metadata remains under `investigations/_dismissed/`
- confirmed incidents are protected from investigation-dismissal cleanup
- integration tests for retain/promote and dismiss/cleanup paths

## Storage rule
Full source events can only enter local storage through an explicit analyst evidence-selection action tied to an investigation or incident.

## Exit criteria
Satisfied. A finding can be investigated, selected evidence can be explicitly retained with provenance, the investigation can be promoted to an incident, and temporary evidence is removed on dismissal.
