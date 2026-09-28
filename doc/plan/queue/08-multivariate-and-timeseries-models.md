# Plan 08 — Multivariate and Time-Series Models

## Goal
Evaluate ML models only after deterministic behavioral detectors and evaluation infrastructure are working.

## Scope
- Isolation Forest over normalized aggregate features.
- Preserve raw component/model scores.
- Backtest against known incidents and benign periods.
- Compare incremental value over novelty/rarity/statistical detectors.
- Evaluate Random Cut Forest for time-series aggregates after Isolation Forest.
- Consider change-point, sequence, and graph methods only where simpler detectors leave measurable gaps.
- Version fitted models per engagement and training window.

## Non-goals
- Do not present model scores as compromise probabilities.
- Do not introduce GPU frameworks or neural models unless evidence demonstrates a need.

## Exit criteria
A model is retained only if it improves operational metrics such as precision@N, incident rank, or lead time without unacceptable noise.
