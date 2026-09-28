# Plan 01 — Persistence Policy and Engagement Storage

## Goal
Enforce the engagement storage policy in code before any detector persists data.

## Completed

Implemented and validated:

- centralized artifact kinds and `PersistencePolicy`
- non-configurable rejection of ordinary raw-event persistence
- engagement-local directory initialization
- purpose-scoped derived stores for features, state, baselines, models, findings, evaluation, and manifests
- path traversal protection
- explicit analyst-selected full-event evidence workflow
- investigation → incident evidence promotion
- dismissal cleanup of temporary evidence
- versioned engagement `config.yaml`
- strict Pydantic config validation with unknown fields rejected
- config is created only when absent and existing config is not silently rewritten
- engagement-configured investigation evidence enable/disable
- engagement-configured temporary evidence retention period
- confirmed incident evidence protected from temporary-investigation cleanup
- `cleanup_expired_investigations()`
- `ctx.config` and `ctx.policy.describe()` inspection
- clean reopen reconstructs the configured policy
- full lifecycle regression tests

The generated `config.yaml` uses JSON syntax, which is valid YAML 1.2, avoiding an additional runtime YAML dependency.

## Framework invariants

- Ordinary raw SIEM events remain in the SIEM.
- Raw query results may exist transiently in notebook/kernel memory.
- Derived behavioral artifacts may be persisted.
- Full events require an explicit analyst evidence-selection action.
- Engagement configuration cannot enable ordinary raw-event archival.
- Confirmed incident evidence is never deleted by temporary-investigation cleanup.

## Exit criteria

Satisfied. Tests demonstrate that derived artifacts can be written, ordinary raw data cannot be archived through package APIs, selected investigation evidence follows engagement policy, and confirmed incident evidence is protected from temporary cleanup.
