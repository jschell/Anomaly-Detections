# Plan 06 — Known Incident Replay and Evaluation

## Goal
Use known malicious/problem datasets to validate detector usefulness and discover relevant features without turning a small incident set into a universal malicious/benign classifier.

## Completed
Implemented and validated:
- typed incident definitions with source/entity/time labels
- pre-incident baseline cutoff and optional earlier exclusion start
- isolated replay workspace so future data cannot leak into the baseline
- matched benign control selection by comparable weekday/hour
- incident rank
- precision@10/@25/@50
- recall@10/@25/@50
- false-positive counts by detector and entity
- time-to-first-signal / lead-time reporting
- detector contribution reporting
- detector ablation rank reporting
- aggregate-feature effect-size reporting
- persisted derived replay reports under `evaluation/replays/`
- regression tests proving replay uses pre-incident state and does not create a raw-event archive

## Principle
Known incidents validate feature and detector behavior. They do not, by themselves, justify universal thresholds or a supervised malicious/benign classifier.

## Exit criteria
Satisfied. A known incident can be replayed against a leakage-safe pre-incident baseline with rank, lead time, detector contribution, false-positive metrics, effect sizes, and ablation reporting.
