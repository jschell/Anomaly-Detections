# Active Plans

The following plans remain active:

1. [00 — Foundation and Package Structure](00-foundation-and-package-structure.md)
2. [01 — Persistence Policy and Engagement Storage](01-persistence-policy-and-engagement-storage.md)
3. [02 — Provider Adapters and Capability Model](02-provider-adapters-and-capability-model.md)

Plans 03–08 are complete and validated.

Current implementation status:

- frozen `uv.lock` CI is green
- typed package/import path is established
- engagement persistence policy is enforced
- behavioral backfill, provenance, coverage, and rhythm baselines work
- explainable detectors and persisted findings work
- known-incident replay and operational metrics work
- analyst investigation/evidence lifecycle is enforced
- Isolation Forest candidates are evaluated against replay metrics before retention
- rejected ML candidates are deleted automatically and further model escalation is deferred

Plans 00–02 remain active because their remaining scope includes public API stabilization, engagement policy configuration/lifecycle handling, and adapter documentation/future-source integration.
