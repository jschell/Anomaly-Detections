# Plan 06 — Known Incident Replay and Evaluation

## Goal
Use known malicious/problem datasets to validate detector usefulness and discover relevant features without overfitting a binary classifier.

## Scope
- Incident definition format with entity/time labels.
- Baseline/model-training exclusion windows.
- Historical replay that prevents future-data leakage.
- Matched benign control selection.
- Metrics: incident rank, precision@10/@25/@50, recall@N, false positives per detector/entity, time-to-first-signal/lead time.
- Feature effect-size analysis.
- Feature ablation.
- Regression tests from known incidents.

## Principle
Known incidents initially validate features and detector behavior; they are not sufficient by themselves to justify universal thresholds or supervised malicious/benign models.

## Exit criteria
At least one known incident can be replayed against a pre-incident baseline with rank, lead-time, detector contribution, and ablation reporting.
