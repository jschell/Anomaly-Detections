# Plan 05 — Core Detectors and Findings

## Goal
Implement the first explainable detector set before introducing heavier ML.

## Completed
Implemented and validated detector families:
1. relationship novelty
2. conditional rarity
3. rhythm-of-business deviation
4. robust historical deviation using median/MAD behavior
5. relationship change
6. organization-relative deviation

A separate hourly volume-deviation signal using historical p95 is also exposed.

Implemented:
- capability-driven detector registry and discovery
- deterministic detector execution
- common typed finding model
- stable finding IDs
- reason codes and analyst-readable explanations
- anomaly/ranking scores rather than malicious-probability claims
- persisted finding artifacts
- source/entity/time SIEM query context without retaining source event payloads
- Entra sign-in regression coverage for novelty, rarity, temporal deviation, volume deviation, relationship change, robust deviation, and organization-relative deviation

## Exit criteria
Satisfied. Entra sign-in data produces explainable findings for novelty, rarity, temporal, historical, relationship, organization-relative, and volume deviations with deterministic regression tests and SIEM pivot context.
