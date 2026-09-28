# Plan 05 — Core Detectors and Findings

## Goal
Implement the first explainable detector set before introducing heavier ML.

## Priority
1. relationship novelty
2. conditional rarity
3. rhythm-of-business deviation
4. robust historical deviation
5. relationship change
6. organization-relative deviation

## Scope
- Common detector interface.
- Detector/feature registry with capability requirements.
- Robust statistics using median/MAD and quantiles.
- Time-conditioned baselines.
- Common finding schema.
- Reason codes and analyst-readable explanation output.
- Persist enough source/entity/time context to pivot back to the SIEM without storing the underlying ordinary raw events.
- Treat detector scores as anomaly/ranking signals, not malicious probabilities.

## Exit criteria
Entra sign-in data produces explainable findings for novelty, rarity, temporal deviation, and volume deviation, with deterministic regression tests and SIEM pivot context.
