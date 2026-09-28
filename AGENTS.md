# AGENTS.md

Instructions for coding agents and contributors working in this repository.

## Operating Model

This is a standalone Python package imported by existing Jupyter/SIEM repositories.

The package does not own SIEM credentials or query execution. Notebook repositories pass in-memory tabular results to this package. The package may persist derived behavioral state in the engagement workspace, but ordinary raw SIEM telemetry must remain in the SIEM.

Read before making changes:

1. `README.md`
2. `doc/overview.md`
3. `doc/plan/README.md`
4. the relevant plan under `doc/plan/active/` or `doc/plan/queue/`

## Project Management Rules

- New plans go to `doc/plan/queue/`.
- When implementation starts, move the plan to `doc/plan/active/`.
- When all exit criteria and validation are complete, move it to `doc/plan/complete/`.
- Do not mark work complete while required tests, lint, type checking, or documented exit criteria are failing.
- Keep plan scope explicit; create a follow-on queued plan rather than silently expanding a plan far beyond its stated goal.

## Python and Dependency Management

Use modern Python conventions.

### Required

- Python >= 3.12
- `uv` for environment management, dependency management, locking, and command execution
- `pyproject.toml` as the dependency and tool configuration source of truth
- commit `uv.lock`
- `src/` package layout
- Ruff
- Pyright
- pytest

### Do not

- add or maintain `requirements.txt` as a second dependency source
- use `pip install ...` in repository documentation when an equivalent `uv` command is appropriate
- manually edit `uv.lock`
- add notebook `sys.path` hacks
- put production implementation only in notebook cells
- introduce dependency managers such as Poetry/Pipenv alongside uv

Add dependencies with uv, for example:

```bash
uv add polars
uv add --dev pytest
```

Then commit both `pyproject.toml` and `uv.lock`.

## Standard Commands

Before considering implementation complete, run:

```bash
uv sync --all-extras --dev
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

Use targeted tests during development, but the full required checks should pass before completion.

## Python Style

- Prefer clear, typed APIs over loose dictionaries.
- Type public functions, methods, and return values.
- Prefer built-in modern generic syntax such as `list[str]` and `dict[str, int]`.
- Prefer `X | None` over `Optional[X]` for new code.
- Use `pathlib.Path` for filesystem paths.
- Use timezone-aware datetimes.
- Prefer immutable/frozen domain records when appropriate.
- Use Pydantic v2 when runtime validation, serialization, or schema generation is needed.
- Do not use Pydantic merely to replace simple internal dataclasses without a validation/serialization need.
- Keep I/O at module boundaries and detection/feature logic as deterministic and testable as practical.
- Avoid provider-specific imports inside generic detectors.
- Avoid hidden global state.

## Package/API Design

The analyst-facing API should stay small.

Target usage:

```python
import siem_anomaly as sa

ctx = sa.open_engagement(path)
ctx.profile(df, source="microsoft.entra_signin")
ctx.discover(df, source="microsoft.entra_signin")
ctx.detect(df, source="microsoft.entra_signin")
```

Provider-specific adapters map source records into provider-neutral semantic capabilities. Generic features and detectors operate on those capabilities.

Support Pandas, Polars, and PyArrow inputs at the package boundary without forcing consuming notebook repositories to rewrite their existing dataframe code.

## Storage and Evidence Rules

This section is mandatory.

### Ordinary telemetry

- Raw ordinary SIEM events may be queried into memory.
- They may be displayed and analyzed in Jupyter.
- They must not be persisted as a general local raw-event archive.
- Do not create a generic raw-event cache or a one-row-per-event shadow SIEM.

### Derived engagement storage

Allowed persisted derived artifacts include:

- aggregate frequencies/counts
- ratios and percentiles
- anomaly feature values
- relationship/entity state
- first/last seen behavioral summaries
- rarity/novelty state
- rhythm-of-business distributions
- historical baselines
- fitted model artifacts
- findings
- analyst labels
- evaluation/backtest results
- provenance/manifests

Persisted behavioral rows should represent aggregates, state, baselines, or findings rather than reproduce the original event stream.

### Incident evidence

Full raw events may be persisted only through the explicit incident/investigation evidence path when they are directly tied to the matter being investigated.

Do not automatically archive raw events because a detector score is high.

Finding -> analyst review -> investigation/incident -> explicit evidence promotion.

### Tests and fixtures

- Never add real customer/SIEM telemetry to the repository.
- Use synthetic fixtures for ordinary tests.
- Regression tests based on incidents should use synthetic/de-identified fixtures unless an explicitly approved test artifact is permitted outside the repository.

## Engagement Isolation

- Every persisted behavioral artifact belongs to an explicit engagement context.
- Do not use global caches that can mix engagement state.
- Models and learned baselines are engagement-specific unless explicitly documented otherwise.
- Cross-environment research must use approved derived evaluation summaries, not centrally combine raw engagement telemetry.

## Feature and Schema Evolution

Because ordinary raw telemetry is not archived locally:

- version feature schemas
- track historical feature coverage
- track adapter/framework versions in manifests
- when a new historical feature is required, re-query the SIEM through the consuming notebook and derive/backfill it
- do not silently treat partial feature history as full 90-day coverage

Confirmed incident windows must be excludable from normal baselines/model training.

## Testing Expectations

Use four broad classes:

- unit tests for algorithms and data contracts
- integration tests for package boundaries and storage
- synthetic behavioral tests for anomaly scenarios
- regression tests for known-incident replay behavior

Tests should explicitly cover:

- no future-data leakage
- engagement isolation
- persistence-policy enforcement
- deterministic feature calculations
- detector explanation output
- schema/feature version handling

Examples intended for users should be executable and preferably exercised by tests.

## Model Guidance

Start with explainable behavioral methods:

1. novelty
2. conditional rarity
3. rhythm-of-business deviation
4. robust historical deviation
5. relationship change
6. organization-relative deviation

Isolation Forest and later time-series/ML methods should only be added after the deterministic evaluation framework works.

A model anomaly score is not a malicious probability.

## Documentation

Update documentation with behavior/API changes.

For meaningful public API changes:
- update `README.md` examples when needed
- update `doc/overview.md` if architecture changes
- update the active plan with material decisions or scope adjustments

Prefer complete runnable examples over pseudocode when documenting actual supported APIs.
