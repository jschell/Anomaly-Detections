# Plan 09 — Provider Expansion and Cross-Source Correlation

## Goal
Validate that the architecture generalizes beyond Microsoft and support cross-source behavioral correlation.

## Completed
Implemented and validated:
- Entra Audit adapter
- Azure Activity adapter
- M365 Audit adapter
- Okta System Log adapter
- AWS CloudTrail adapter
- GCP Audit Log adapter
- generic capability-driven reuse on Okta identity data
- generic behavioral feature/detector reuse on AWS CloudTrail control-plane data
- provider-specific notable-action packs for Microsoft, Okta, AWS, and GCP sources
- explicit alias-to-canonical-entity resolver with confidence thresholds
- cross-source finding correlation by canonical identity, time, source IP, application, and resource dimensions
- correlation operates only on findings/derived dimensions, not centralized raw telemetry
- integration tests proving Entra/Okta cross-source correlation and AWS generic detector reuse

## Exit criteria
Satisfied. A non-Microsoft identity source (Okta) and a non-Azure cloud-control source (AWS CloudTrail) reuse generic detector families, and correlated findings are produced without mixing raw telemetry stores.
