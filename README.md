# Anomaly-Detections

Reusable Python anomaly-detection and behavioral-analytics framework for SIEM-backed Jupyter workflows.

The project is intentionally separate from the notebook repositories that query SIEM data. Existing notebooks remain responsible for authentication, query execution, and interactive investigation. This package consumes in-memory tabular results, derives engagement-local behavioral state, runs detectors, and returns explainable findings.

See [doc/overview.md](doc/overview.md) for the architecture and storage model.

## Project Principles

- SIEM remains the system of record for ordinary raw telemetry.
- Raw query results may exist transiently in notebook/kernel memory but are not archived by this package.
- Derived behavioral features, relationship state, rhythm-of-business baselines, models, findings, and evaluation artifacts may be stored in the engagement workspace.
- Full raw events may be retained only through the explicit incident/investigation evidence workflow.
- The package is provider-neutral at its core. Microsoft is first; Okta, AWS, and GCP are planned.
- Generic detectors depend on semantic capabilities, not provider modules.
- Detector scores are anomaly/ranking signals, not probabilities that activity is malicious.

## Python Tooling

This repository uses modern Python project conventions inspired by the Model Context Protocol Python SDK:

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) for environments, dependency management, locking, and command execution
- `pyproject.toml` as the project/tooling source of truth
- committed `uv.lock`
- `src/` package layout
- Ruff for linting and formatting
- Pyright for static type checking
- pytest for tests
- Pydantic v2 where runtime validation/serialization is useful

Do not introduce a parallel `requirements.txt` workflow.

## Development Setup

Install uv if it is not already available, then:

```bash
uv sync --frozen --all-extras --dev
```

Run the required checks:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

For active development from a sibling notebook repository:

```bash
uv pip install -e ../Anomaly-Detections
```

The preferred long-term integration is a versioned Git or package dependency rather than notebook `sys.path` manipulation.

## Notebook Workflow

The public API is intentionally small and typed.

```python
import siem_anomaly as sa

ctx = sa.open_engagement(engagement_path)

# Understand the current source and available detectors.
profile = ctx.profile(df, source="microsoft.entra_signin")
available = ctx.discover(df, source="microsoft.entra_signin")

# Backfill behavioral history from SIEM query windows.
ctx.derive(
    historical_df,
    source="microsoft.entra_signin",
    query_id="entra:2026-07-01:2026-09-28",
    window_start=window_start,
    window_end=window_end,
)

# Check historical coverage and rebuild time-conditioned baselines.
missing = ctx.missing_windows(start=lookback_start, end=lookback_end)
ctx.rebuild_baselines()

# Analyze current/transient SIEM results.
findings = ctx.detect(df, source="microsoft.entra_signin")
```

Notebook repositories own SIEM access. This package does not own credentials or provider query execution.

## Implemented Behavioral State

Current derived families include:

- actor-hour
- actor-day
- service-hour
- resource-hour
- operation-hour
- environment-hour
- actor → IP
- actor → application
- actor → country
- actor → resource
- actor → operation
- actor and environment weekday/hour rhythm baselines

The framework stores these derived structures as engagement-local Parquet rather than retaining an ordinary raw-event archive.

## Implemented Core Detectors

Current explainable identity detectors include:

- relationship novelty
- conditional rarity
- relationship change
- rhythm-of-business deviation
- hourly volume deviation
- robust historical deviation
- organization-relative deviation

Findings include stable IDs, source/entity/time context, reason codes, analyst-readable explanations, and enough context to pivot back to the SIEM.

## Historical Coverage and Provenance

Each derived query partition records:

- feature set/version
- source
- query ID and hash
- queried time range
- source rows processed
- derived rows produced
- adapter/framework versions
- overlap/rebuild strategy

Empty SIEM result windows can still be recorded when `window_start` and `window_end` are supplied. This allows coverage to represent the actual queried period rather than only periods where events existed.

## Repository Layout

```text
.
├── AGENTS.md
├── README.md
├── pyproject.toml
├── uv.lock
├── doc/
│   ├── overview.md
│   └── plan/
│       ├── active/
│       ├── complete/
│       └── queue/
├── src/
│   └── siem_anomaly/
└── tests/
    ├── unit/
    ├── integration/
    ├── synthetic/
    └── regression/
```

## Plan Workflow

Plans live under `doc/plan/`:

- `queue/` — planned work not started
- `active/` — work currently being implemented
- `complete/` — implemented and validated

New plans are created in `queue/` and move through `active/` to `complete/`.

See [doc/plan/README.md](doc/plan/README.md) for details.

## Storage Boundary

Allowed engagement-local persisted artifacts include:

- aggregate behavioral features
- relationship/entity state
- rhythm-of-business and historical baselines
- model artifacts
- anomaly findings
- evaluation and analyst labels
- manifests/provenance
- selected full events explicitly promoted into incident evidence

Ordinary raw SIEM events must not be archived by this package.

## Status

The first usable milestone through Plans 03–05 is complete. The package can build behavioral history from SIEM-backed notebook queries, track/backfill coverage, and produce explainable Entra sign-in anomaly findings without retaining ordinary raw telemetry.
