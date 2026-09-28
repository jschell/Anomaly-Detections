# Feature Registry and Portability

The feature registry documents why a persisted or on-demand feature exists.

Each `FeatureDefinition` records:

- feature ID and version
- behavioral family
- whether it is persisted
- storage class and resolution
- detector consumers
- maturity: experimental, candidate, validated, core, or deprecated
- expected portability: high, medium, low, or unknown
- description

## Portability evaluation

Per-engagement evaluation produces metrics-only `EnvironmentFeatureMetrics` summaries. These can include:

- effect size
- incident recall
- precision@25
- false-positive rate
- rank contribution
- ablation delta

`summarize_replay_feature()` converts Plan 06 replay results into this metrics-only representation.

Cross-environment research may use only summaries explicitly marked `approved_for_export`. Raw telemetry and detailed relationship state are not accepted by the export API.

`assess_portability()` reports high/medium/low evidence based on repeated environment results, and `leave_one_environment_out()` checks whether observed recall generalizes to held-out environments once at least three environments are available.
