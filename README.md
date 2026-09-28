# Anomaly-Detections

Reusable Python anomaly-detection and behavioral-analytics framework for SIEM-backed Jupyter workflows.

The project is intentionally separate from notebook repositories that query SIEM data. Existing notebooks remain responsible for authentication, query execution, and interactive investigation. This package consumes in-memory tabular results, derives engagement-local behavioral state, runs detectors, evaluates findings against known incidents, correlates findings across providers, and supports controlled investigation/evidence workflows.

See [doc/overview.md](doc/overview.md) for the architecture and storage model.

## Project Principles

- SIEM remains the system of record for ordinary raw telemetry.
- Raw query results may exist transiently in notebook/kernel memory but are not archived by this package.
- Derived behavioral features, relationship state, rhythm-of-business baselines, models, findings, and evaluation artifacts may be stored in the engagement workspace.
- Full raw events may be retained only through explicit analyst selection tied to an investigation/incident.
- Generic detectors depend on semantic capabilities, not provider modules.
- Detector/model scores are anomaly/ranking signals, not compromise probabilities.
- Heavier models are retained only when measured operational metrics improve.
- Cross-environment research uses approved metrics-only summaries, not centralized raw telemetry or detailed relationship stores.

## Supported Provider Adapters

Built-in adapters currently include:

- Microsoft Entra sign-in
- Microsoft Entra Audit
- Azure Activity
- Microsoft 365 Audit
- Okta System Log
- AWS CloudTrail
- GCP Audit Logs

See [doc/provider-adapters.md](doc/provider-adapters.md).

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

ctx.rebuild_baselines()
findings = ctx.detect(current_df, source="microsoft.entra_signin")
```

The same capability-driven pipeline can operate on Okta and cloud-control sources where the required canonical fields are available.

## Cross-Source Correlation

Canonical entity aliases are explicitly mapped with confidence; the framework does not guess identity equivalence.

Findings can then be correlated across sources by:

- canonical identity
- time proximity
- source IP
- application/service
- resource

Correlation operates on findings and derived dimensions rather than combining source event archives.

## Feature Registry and Portability

The formal feature registry records feature version, family, persistence/storage class, consumers, maturity, and expected portability.

Per-engagement replay can be converted into metrics-only feature summaries containing effect size, incident recall, precision@25, false-positive rate, rank contribution, and ablation delta.

Approved summaries can be compared across environments, assigned high/medium/low portability evidence, and evaluated with leave-one-environment-out validation once enough environments exist.

See [doc/feature-registry.md](doc/feature-registry.md).

## Storage Boundary

Allowed engagement-local artifacts include derived features/state, baselines, retained model artifacts, findings, evaluation results, provenance, analyst labels/notes, and explicitly selected incident evidence.

Ordinary raw SIEM events must not be archived by this package.

## Development

```bash
uv sync --frozen --all-extras --dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

## Status

Plans 00–10 are complete and validated. There are currently no active or queued roadmap plans.

The framework supports typed notebook integration, controlled engagement persistence, multi-provider behavioral analytics, explainable detection, known-incident evaluation, explicit evidence retention, gated model evaluation, cross-source finding correlation, and metrics-only cross-environment feature-portability research.
