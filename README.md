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
uv sync --all-extras --dev
```

Run the required checks:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

For active development from a sibling notebook repository, install this package editable:

```bash
uv pip install -e ../Anomaly-Detections
```

The preferred long-term integration is a versioned Git or package dependency rather than notebook `sys.path` manipulation.

## Intended Notebook Usage

The public API should remain small and typed.

```python
import siem_anomaly as sa

ctx = sa.open_engagement(engagement_path)

profile = ctx.profile(df, source="microsoft.entra_signin")
available = ctx.discover(df, source="microsoft.entra_signin")
findings = ctx.detect(df, source="microsoft.entra_signin")
```

Notebook repositories own SIEM access; this package does not own credentials or provider query execution.

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

The implementation layout will be completed under Plan 00.

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

The repository is currently in planning/foundation stage. Implementation begins with the queued plans under `doc/plan/queue/`.
