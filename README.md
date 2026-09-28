# Anomaly-Detections

Reusable Python anomaly-detection and behavioral-analytics framework for SIEM-backed Jupyter workflows.

The project is intentionally separate from notebook repositories that query SIEM data. Existing notebooks remain responsible for authentication, query execution, and interactive investigation. This package consumes in-memory tabular results, derives engagement-local behavioral state, runs detectors, evaluates findings against known incidents, and supports controlled investigation/evidence workflows.

See [doc/overview.md](doc/overview.md) for the architecture and storage model.

## Project Principles

- SIEM remains the system of record for ordinary raw telemetry.
- Raw query results may exist transiently in notebook/kernel memory but are not archived by this package.
- Derived behavioral features, relationship state, rhythm-of-business baselines, models, findings, and evaluation artifacts may be stored in the engagement workspace.
- Full raw events may be retained only through explicit analyst selection tied to an investigation/incident.
- The package is provider-neutral at its core. Microsoft is first; Okta, AWS, and GCP are planned.
- Generic detectors depend on semantic capabilities, not provider modules.
- Detector/model scores are anomaly/ranking signals, not compromise probabilities.
- Heavier models are retained only when measured operational metrics improve.

## Python Tooling

- Python 3.12+
- uv for environment/dependency/lock management
- committed `uv.lock`
- `pyproject.toml` as source of truth
- `src/` package layout
- Ruff
- strict Pyright
- pytest

```bash
uv sync --frozen --all-extras --dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

## Notebook Workflow

```python
import siem_anomaly as sa

ctx = sa.open_engagement(engagement_path)

profile = ctx.profile(df, source="microsoft.entra_signin")
available = ctx.discover(df, source="microsoft.entra_signin")

ctx.derive(
    historical_df,
    source="microsoft.entra_signin",
    query_id="entra:2026-07-01:2026-09-28",
    window_start=window_start,
    window_end=window_end,
)

missing = ctx.missing_windows(start=lookback_start, end=lookback_end)
ctx.rebuild_baselines()

findings = ctx.detect(current_df, source="microsoft.entra_signin")
```

Notebook repositories own SIEM access. This package does not own credentials or provider query execution.

## Behavioral State

Current derived families include:

- actor-hour / actor-day
- service-hour / resource-hour / operation-hour / environment-hour
- actor → IP/application/country/resource/operation
- actor and environment weekday/hour rhythm baselines

Only derived behavioral state is persisted by default.

## Explainable Detectors

Current identity detectors include:

- relationship novelty
- conditional rarity
- relationship change
- rhythm-of-business deviation
- hourly volume deviation
- robust historical deviation
- organization-relative deviation

Findings include stable IDs, source/entity/time context, reason codes, explanations, and SIEM pivot context.

## Known-Incident Replay

Known incidents can be evaluated against a leakage-safe pre-incident baseline.

Replay reports include:

- incident rank
- precision@10/@25/@50
- recall@10/@25/@50
- false positives by detector/entity
- time-to-first-signal
- detector contribution
- feature effect sizes
- detector ablation rank

Replay uses a temporary derived workspace; ordinary source events are not archived.

## Analyst Investigation and Evidence

The explicit workflow is:

`finding → investigating → incident` or `finding → investigating → dismissed`.

Selected full events may be retained only through an analyst action with a selection reason. Temporary investigation evidence is removed when dismissed. Confirmed incident evidence is retained under the incident workspace with provenance manifests.

## Multivariate Models

Isolation Forest is implemented over derived actor-hour aggregates.

Models follow a candidate lifecycle:

`train candidate → score/backtest → compare to deterministic replay → retain or delete`.

Raw score components, decision function, anomaly rank, training window, and feature version are preserved.

A candidate is retained only if incident rank or precision@N improves. Otherwise it is deleted. Random Cut Forest escalation is deferred unless Isolation Forest first demonstrates incremental value on an evaluated workload.

## Historical Coverage and Provenance

Each derived query partition records feature version, source, query ID/hash, queried time range, source/derived row counts, adapter/framework versions, and overlap strategy.

Empty SIEM result windows can still be recorded, allowing coverage to represent the actual queried period.

## Plan Workflow

Plans live under `doc/plan/`:

- `queue/` — planned
- `active/` — currently executing
- `complete/` — implemented and validated

## Storage Boundary

Allowed engagement-local artifacts include derived features/state, baselines, retained model artifacts, findings, evaluation results, provenance, analyst labels/notes, and explicitly selected incident evidence.

Ordinary raw SIEM events must not be archived by this package.

## Status

Plans 03–08 are complete. The project now supports an end-to-end Entra sign-in workflow from SIEM-backed Jupyter queries through behavioral baselines, explainable anomaly detection, known-incident evaluation, controlled incident evidence retention, and gated multivariate-model evaluation.
