# Queued Plans

Current intended sequence:

1. [00 — Foundation and Package Structure](00-foundation-and-package-structure.md)
2. [01 — Persistence Policy and Engagement Storage](01-persistence-policy-and-engagement-storage.md)
3. [02 — Provider Adapters and Capability Model](02-provider-adapters-and-capability-model.md)
4. [03 — Derived Features, State, and Rhythm of Business](03-derived-feature-state-and-rhythm.md)
5. [04 — Provenance, Feature Versioning, and Backfill](04-provenance-feature-versioning-and-backfill.md)
6. [05 — Core Detectors and Findings](05-core-detectors-and-findings.md)
7. [06 — Known Incident Replay and Evaluation](06-known-incident-replay-and-evaluation.md)
8. [07 — Incident Evidence and Analyst Workflow](07-incident-evidence-and-analyst-workflow.md)
9. [08 — Multivariate and Time-Series Models](08-multivariate-and-timeseries-models.md)
10. [09 — Provider Expansion and Cross-Source Correlation](09-provider-expansion-and-cross-source-correlation.md)
11. [10 — Cross-Environment Feature Portability Research](10-feature-portability-research.md)

The first implementation milestone is the end of Plan 05: a separate package can be imported by the existing notebook repository, derive engagement-local behavioral state without archiving ordinary raw events, and return explainable Entra sign-in findings.
