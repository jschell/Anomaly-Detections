# Plan 08 — Multivariate and Time-Series Models

## Goal
Evaluate ML only after deterministic behavioral detectors and known-incident evaluation infrastructure are working.

## Completed
Implemented and validated:
- Isolation Forest over normalized derived actor-hour aggregate features
- no raw-event model training
- engagement-local candidate model artifacts
- model metadata with feature version and training window
- raw `score_samples`, decision function, anomaly ranking score, and model flag preserved
- direct comparison against deterministic replay metrics
- comparison uses incident rank and precision@N
- candidate → evaluate → retain/delete lifecycle
- rejected model candidates are deleted automatically
- accepted candidates are moved into the retained model namespace
- tests cover both retained and rejected model paths
- time-series escalation gate for Random Cut Forest

## Random Cut Forest decision
RCF is intentionally not a required dependency at this stage.

The implemented gate behaves as follows:
- if Isolation Forest does not demonstrate incremental operational value, RCF evaluation is deferred and model escalation stops
- if Isolation Forest is retained on an evaluated workload, RCF becomes a candidate for a subsequent time-series-specific benchmark

The current replay-backed synthetic regression demonstrates the no-improvement path and correctly rejects the Isolation Forest candidate, so adding an RCF dependency is not justified by current evidence.

## Non-goals preserved
- model scores are not compromise probabilities
- no GPU/neural framework was introduced
- additional model families are not added merely because they exist

## Exit criteria
Satisfied. Model artifacts are retained only through an explicit evaluation gate demonstrating better incident rank or precision; otherwise the candidate is removed and further model escalation is deferred.
