# Plan 10 — Cross-Environment Feature Portability Research

## Goal
Identify behavioral properties of known malicious activity that generalize across engagements without creating a cross-customer telemetry repository.

## Completed
Implemented and validated:
- formal feature registry
- feature versions, families, persistence/storage classes, consumers, maturity, and portability metadata
- core/candidate/validated maturity distinctions
- replay-derived metrics-only feature summaries
- effect size
- incident recall
- precision@25
- false-positive rate
- rank contribution
- ablation delta
- high/medium/low portability assessment
- leave-one-environment-out validation when at least three environments are available
- explicitly approved-only export of cross-environment summaries
- no export API for raw telemetry or detailed relationship state
- tests demonstrating portability assessment, LOEO behavior, and export filtering

## Exit criteria
Satisfied. The framework can state which registered features have been tested in which environments, summarize their performance, assign high/medium/low portability evidence, and perform held-out-environment validation using metrics-only data.
