# Plan 10 — Cross-Environment Feature Portability Research

## Goal
Identify behavioral properties of known malicious activity that generalize across engagements without creating a cross-customer telemetry repository.

## Scope
- Formal feature registry with portability metadata.
- Normalize candidate features using percentiles, ratios, rarity, novelty, conditional probability, and relative deviation.
- Compare malicious windows to matched benign controls.
- Track effect sizes, rank contribution, incident recall, precision@N, false-positive rates, and ablation results.
- Support leave-one-environment-out validation when enough engagements exist.
- Export only explicitly approved feature-performance/evaluation summaries for cross-environment research.
- Do not centrally combine raw telemetry or detailed engagement relationship state.

## Exit criteria
The framework can state which features have been tested in which environments, how they performed, and whether evidence supports high/medium/low portability.
