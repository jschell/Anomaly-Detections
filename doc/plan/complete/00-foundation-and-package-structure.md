# Plan 00 — Foundation and Package Structure

## Goal
Create the standalone, versioned `siem_anomaly` Python package that existing Jupyter/SIEM repositories can import, using modern Python and uv conventions.

## Completed

Implemented and validated:

- Python >=3.12, `src/` package layout, `pyproject.toml`, and committed `uv.lock`
- typed `open_engagement()` and `EngagementContext`
- public profile, discovery, derive/detect, replay/evaluation, model, correlation, and analyst-workflow paths
- Pandas, Polars, and PyArrow inputs at the package boundary
- provider-neutral domain/capability/finding records
- Ruff, strict Pyright, pytest, package build configuration, and frozen-lock CI
- executable notebook-facing usage examples
- no parallel requirements/Poetry/Pipenv dependency source
- no notebook `sys.path` integration requirement
- engagement isolation and raw-telemetry storage boundaries enforced by later completed plans

Later plans stabilized the detection/evaluation and incident APIs that were intentionally placeholders when this foundation plan began.

## Exit criteria

Satisfied. A consuming notebook can import the package, open an engagement, profile/discover supported in-memory dataframe inputs without provider coupling, and use the typed analyst-facing APIs. Clean-checkout frozen uv sync, lint, formatting, strict typing, and tests pass in CI.
