# Plan 00 — Foundation and Package Structure

## Goal
Create the standalone, versioned `siem_anomaly` Python package that existing Jupyter/SIEM repositories can import.

## Scope
- Create `pyproject.toml` and `src/siem_anomaly/` package layout.
- Define stable public API around `open_engagement()`, profiling, discovery, detection, evaluation, and incident handling.
- Support Pandas, Polars, and PyArrow inputs through adapters.
- Define provider-neutral core types: event envelope, actor, resource, capability, finding, engagement context.
- Add linting, typing, unit tests, package build, and CI.
- Document install patterns: editable local development, Git pin, and versioned package release.

## Design constraints
- The package does not own SIEM credentials or query execution.
- Generic detectors must not import provider-specific modules.
- No global cross-engagement cache.
- The consuming notebook and anomaly package run in the same Python kernel.

## Deliverables
- Importable `siem_anomaly` package.
- `EngagementContext` skeleton.
- Dataframe adapter tests.
- CI workflow.
- Basic example showing import from a notebook repository.

## Exit criteria
A notebook in a separate repository can install/import the package, open an engagement context, and pass a dataframe through a no-op/profile path without provider-specific coupling.
