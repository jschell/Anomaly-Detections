# Plan 09 — Provider Expansion and Cross-Source Correlation

## Goal
Validate that the architecture generalizes beyond Microsoft and support cross-source behavioral correlation.

## Planned sequence
1. Entra Audit / service principals
2. Azure Activity
3. M365 Audit
4. Okta System Log — identity portability test
5. AWS CloudTrail/IAM — cloud-control portability test
6. GCP Audit Logs/IAM — cross-cloud portability test

## Scope
- Add adapters and provider-specific detector packs.
- Reuse generic capability-driven detectors where semantics match.
- Add canonical identity/entity-resolution layer with aliases and confidence before correlating identities across providers.
- Correlate findings by canonical entity, time, IP, application, and resource relationships.
- Correlation operates on findings/derived state rather than a centralized raw-event store.

## Exit criteria
At least one non-Microsoft identity source and one non-Azure cloud-control source can reuse generic detector families, and correlated findings can be produced without mixing raw telemetry stores.
