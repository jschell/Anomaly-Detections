# Plan 01 — Persistence Policy and Engagement Storage

## Goal
Enforce the engagement storage policy in code before any detector persists data.

## Core policy
- Ordinary raw SIEM events remain in the SIEM.
- Raw query results may exist transiently in notebook/kernel memory.
- Aggregated behavioral features, state, baselines, models, findings, manifests, and evaluation artifacts may be persisted.
- Full events may be persisted only through explicit incident/investigation evidence promotion.
- Persisted behavioral datasets must not become a one-row-per-source-event shadow SIEM.

## Scope
- Define artifact classes: transient event, aggregate feature, relationship state, baseline, model, finding, evaluation result, incident evidence.
- Add purpose-specific writers; do not expose a generic dataframe archive API.
- Build engagement-local directory management.
- Add retention/lifecycle hooks for investigating vs confirmed incident evidence.
- Add validation preventing unsupported persistence paths.
- Add `config.yaml` schema for engagement-specific policy.

## Target engagement layout
`features/`, `state/`, `baselines/`, `models/`, `findings/`, `evaluation/`, `incidents/`, `manifests/`.

## Exit criteria
Tests demonstrate that derived artifacts can be written, ordinary raw data cannot be archived through package APIs, and incident evidence requires an explicit promotion path.
