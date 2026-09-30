# Anomaly Detection Framework Overview

## Purpose

This repository provides a reusable Python anomaly-detection and behavioral-analytics framework intended to be imported by existing Jupyter notebook repositories that already query SIEM data.

Notebook repositories remain responsible for authentication, SIEM connectivity, query execution, transient raw DataFrames, and interactive investigation. This package consumes in-memory tabular results and maintains derived behavioral state, models, findings, correlation artifacts, and evaluation summaries.

## Implemented Architecture

```text
SIEM / source systems
        |
        | transient notebook query results
        v
provider adapters
        |
        v
canonical semantic capabilities
        |
        +--> derived behavioral features / relationship state
        +--> rhythm-of-business baselines
        +--> generic detectors
        +--> provider-specific notable-action packs
        |
        v
findings
        |
        +--> SIEM pivot / analyst investigation
        +--> cross-source finding correlation
        +--> known-incident replay/evaluation
        |
        v
engagement-local derived storage
```

Ordinary raw telemetry remains in the SIEM. Full source events may be retained only through the explicit investigation/incident evidence workflow.

## Providers

Implemented adapters:

- Microsoft Entra sign-in
- Microsoft Entra Audit
- Azure Activity
- Microsoft 365 Audit
- Okta System Log
- AWS CloudTrail
- GCP Audit Logs

Provider-specific field names map into canonical concepts such as timestamp, actor, source IP, application/service, action, target/resource, region, and outcome.

Generic detectors depend on capabilities rather than importing provider modules.

## Behavioral State

Persisted behavioral state includes actor-hour/day, service/resource/operation/environment hourly aggregates, actor relationship state, and actor/environment rhythm baselines.

Relationship state emphasizes behavioral summaries such as first/last seen date, count, days seen, and rarity rather than reconstructing individual event histories.

## Detection

Implemented explainable detector families include relationship novelty, conditional rarity, relationship change, rhythm deviation, volume deviation, robust historical deviation, and organization-relative deviation.

Provider-specific notable-action packs add source-aware prioritization signals while explicitly avoiding claims that the action itself is malicious.

## Cross-Source Correlation

Entity equivalence is explicit rather than inferred.

An alias resolver maps provider-specific identities to canonical entity IDs with confidence. Findings can then be clustered across providers using canonical identity, time proximity, source IP, application, and resource dimensions.

Correlation operates on findings/derived dimensions and does not merge raw telemetry stores.

## Evaluation and Models

Known incidents can be replayed against leakage-safe pre-incident baselines. Metrics include rank, precision/recall at analyst-reviewable cutoffs, false positives, lead time, effect sizes, and detector ablation.

Isolation Forest is supported over derived aggregate features, but candidates are retained only when replay metrics demonstrate incremental operational value. Further model escalation is deferred otherwise.

## Feature Portability Research

The formal feature registry tracks feature identity/version, family, persistence, storage class, detector consumers, maturity, and expected portability.

Per-engagement replay results can be converted to approved metrics-only feature summaries. Cross-environment research operates on those summaries and supports high/medium/low portability assessment and leave-one-environment-out validation.

Raw customer telemetry and detailed relationship stores are never combined for cross-environment research.

## Plan Workflow

`doc/plan/active/` contains work still in progress, `complete/` contains validated plans, and `queue/` contains future plans.

Plans 00–10 are complete and validated. Plan 11, optional network enrichment and behavioral detection, is queued; there are no active roadmap plans.
