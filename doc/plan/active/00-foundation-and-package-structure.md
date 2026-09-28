# Plan 00 — Foundation and Package Structure

## Goal
Create the standalone, versioned `siem_anomaly` Python package that existing Jupyter/SIEM repositories can import, using the repository's modern Python and uv conventions.

## Progress

Implemented:
- root `README.md` and `AGENTS.md`
- Python >=3.12, uv-first `pyproject.toml`, and committed `uv.lock`
- `src/siem_anomaly/` package
- typed `open_engagement()` / `EngagementContext`
- Pandas, Polars, and PyArrow input support
- provider-neutral actor/resource/event/finding records
- Ruff, strict Pyright, pytest, and frozen-lock GitHub Actions CI
- executable notebook integration example
- CI currently passes `uv sync --frozen --all-extras --dev`, Ruff, Pyright, and pytest

Remaining before completion:
- stabilize the public detection/evaluation methods that depend on later detector/evaluation plans
- add explicit package-level API documentation for those methods once their contracts exist
- decide whether Plan 00 should close with placeholders for later APIs or wait until the first detector path exists

## Scope
- Finalize `src/siem_anomaly/` package layout.
- Generate dependency resolution with `uv` and commit `uv.lock`; never hand-author the lockfile.
- Define stable public API around `open_engagement()`, profiling, discovery, detection, evaluation, and incident handling.
- Support Pandas, Polars, and PyArrow inputs through adapters.
- Define provider-neutral core types: event envelope, actor, resource, capability, finding, engagement context.
- Add/finalize linting, strict typing, unit tests, package build, and CI.
- Document install patterns: editable local development, Git pin, and versioned package release.
- Ensure user-facing examples are executable/testable where practical.

## Required development workflow
Use:

```bash
uv sync --all-extras --dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

Dependencies must be added with `uv add` / `uv add --dev` (or the appropriate uv dependency-group command), with `pyproject.toml` and `uv.lock` committed together.

Do not introduce:
- a parallel `requirements.txt` dependency workflow
- Poetry/Pipenv
- notebook `sys.path` hacks
- production logic that exists only in notebook cells

## Design constraints
- The package does not own SIEM credentials or query execution.
- Generic detectors must not import provider-specific modules.
- No global cross-engagement cache.
- The consuming notebook and anomaly package run in the same Python kernel.
- Ordinary raw SIEM telemetry is never persisted as a general local archive.
- Full raw events are persisted only through the explicit incident/investigation evidence workflow.

## Deliverables
- Importable `siem_anomaly` package.
- Committed `uv.lock`.
- `EngagementContext` skeleton.
- Pandas/Polars/PyArrow dataframe adapter tests.
- Provider-neutral core types.
- Ruff/Pyright/pytest configuration passing.
- CI workflow that performs frozen uv sync and required quality gates.
- Basic executable example showing import from a separate notebook repository.

## Exit criteria
A notebook in a separate repository can install/import the package, open an engagement context, and pass a dataframe through a no-op/profile path without provider-specific coupling.

The following all pass from a clean checkout:

```bash
uv sync --frozen --all-extras --dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

No second dependency source exists, `uv.lock` is committed, and the public API is typed and documented.
