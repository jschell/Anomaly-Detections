# Plan 04 — Provenance, Feature Versioning, and Backfill

## Goal
Make derived analysis reproducible even though ordinary raw events are not retained locally.

## Completed
Implemented and validated:
- manifest per derived query partition
- source, query ID/hash, queried time window, source rows, derived rows, adapter version, feature version, and framework version
- independent feature-version tracking
- exact coverage reporting
- missing-window calculation
- explicit support for empty SIEM result windows so coverage reflects the query, not only returned events
- idempotent query partition replacement using stable query IDs
- baseline rebuild from persisted derived feature state
- integration tests for gap detection, empty-window coverage, and repeated partition replacement

## Example workflow

```python
coverage = ctx.coverage(feature_version="identity-v1")
missing = ctx.missing_windows(
    start=start,
    end=end,
    feature_version="identity-v1",
)

for window in missing:
    df = query_siem(window.start, window.end)
    ctx.derive(
        df,
        source="microsoft.entra_signin",
        query_id=f"entra:{window.start}:{window.end}",
        window_start=window.start,
        window_end=window.end,
    )

ctx.rebuild_baselines()
```

## Exit criteria
Satisfied. The package reports exact derived coverage and provenance, identifies feature-version gaps, records empty query windows, and supports notebook-driven historical backfill/rebuild.
