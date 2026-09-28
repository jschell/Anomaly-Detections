# Plan 04 — Provenance, Feature Versioning, and Backfill

## Goal
Make derived analysis reproducible even though ordinary raw events are not retained locally.

## Scope
- Manifest every derived partition with source, query ID/hash, time range, source rows processed, derived rows produced, adapter version, feature-set version, and framework version.
- Version feature schemas independently from package versions.
- Track historical coverage per feature set.
- Detect gaps after feature schema changes.
- Expose missing-window calculation so the notebook can re-query the SIEM.
- Support controlled rebuild/recompute of derived state.
- Add late-arrival overlap/deduplication strategy where aggregation requires it.

## Example workflow
`ctx.features.coverage()` → identify missing v3 history → notebook queries SIEM → `ctx.derive(df,...)` → raw dataframe discarded.

## Exit criteria
The package can report exact feature coverage and provenance, detect a newly added feature needing historical backfill, and rebuild it through notebook-provided SIEM data.
