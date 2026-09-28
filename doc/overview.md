# Anomaly Detection Framework Overview

## Purpose

This repository will provide a reusable Python anomaly-detection and behavioral-analytics framework intended to be imported by existing Jupyter notebook repositories that already query SIEM data.

The framework is intentionally separate from SIEM query notebooks. Notebook repositories remain responsible for authentication, SIEM connectivity, KQL or other provider-specific query execution, and interactive investigation. This repository consumes in-memory tabular results and maintains derived behavioral state, models, findings, and evaluation artifacts.

## Intended Shape

```text
Existing Jupyter / SIEM repository
        |
        | query results (Pandas / Polars / Arrow)
        v
Anomaly-Detections package
        |
        +-- provider adapters
        +-- feature extraction
        +-- relationship state
        +-- rhythm-of-business baselines
        +-- anomaly detectors
        +-- evaluation / incident replay
        +-- findings / explanations
        |
        v
Engagement-local derived storage
```

The package should be installable into the same Python environment as the consuming notebooks and imported with a small analyst-facing API.

Example target usage:

```python
import siem_anomaly as sa

ctx = sa.open_engagement(engagement_path)

profile = ctx.profile(df, source="microsoft.entra_signin")
available = ctx.discover(df, source="microsoft.entra_signin")
findings = ctx.detect(df, source="microsoft.entra_signin")
```

## Repository Boundaries

### Existing notebook repositories own

- SIEM credentials and authentication
- SIEM query execution
- provider/query-specific retrieval logic
- transient raw DataFrames
- interactive analyst investigation
- pivots back to source telemetry

### This repository owns

- provider adapters and semantic mappings
- capability discovery
- derived feature generation
- relationship and entity state
- historical and rhythm-of-business baselines
- novelty, rarity, statistical, and later ML detectors
- detector and feature catalogs
- finding schemas and explanations
- known-incident replay and backtesting
- feature portability research
- engagement-local persistence controls

## Storage Policy

The SIEM remains the authoritative system of record for ordinary raw telemetry.

### Raw events

Ordinary raw events:

- may be queried into notebook memory
- may be displayed and investigated
- must not be persisted as a general local archive

Full raw events may be retained only when they are directly associated with an active investigation or incident and are explicitly promoted into the incident evidence store.

### Derived data

The engagement folder may persist derived behavioral information such as:

- frequencies and counts
- ratios and percentiles
- anomaly feature values
- entity and relationship state
- first/last seen behavioral summaries
- rarity and novelty summaries
- rhythm-of-business distributions
- historical baselines
- trained model artifacts
- findings
- analyst labels
- backtest/evaluation results
- provenance/manifests

Persisted behavioral rows should represent aggregates, relationship state, baselines, or findings rather than one persisted row per source event.

## Engagement-Local Storage

A consuming notebook points the package at an engagement-specific workspace.

Target layout:

```text
engagement/
└── anomaly/
    ├── config.yaml
    ├── manifests/
    ├── features/
    │   ├── actor_hour/
    │   ├── actor_day/
    │   ├── service_hour/
    │   ├── resource_hour/
    │   └── operation_hour/
    ├── state/
    │   ├── entity/
    │   ├── relationships/
    │   └── temporal/
    ├── baselines/
    │   ├── entity/
    │   ├── organization/
    │   └── rhythm/
    ├── models/
    ├── findings/
    ├── evaluation/
    │   ├── known_incidents/
    │   ├── exclusions/
    │   ├── labels/
    │   └── replay_results/
    └── incidents/
        └── INC-*/
            ├── manifest.yaml
            ├── events.parquet
            ├── findings.json
            └── notes/
```

The package must not use a global behavioral cache that mixes engagements.

## Provider-Neutral Design

Microsoft is the first provider family, not the architecture.

The core package should work from provider-neutral semantic concepts such as:

- timestamp
- actor
- actor type
- action
- target/resource
- source IP
- application/service
- outcome
- region
- device
- authentication context

Provider adapters map source-specific records into those concepts while retaining provider-specific semantics for specialized detections.

Planned provider families:

- Microsoft Entra ID
- Azure Activity
- Microsoft 365 audit
- Okta System Log
- AWS CloudTrail / IAM / sign-in related telemetry
- GCP Audit Logs / IAM related telemetry

Generic detectors must depend on capabilities and semantic fields, not import provider-specific adapters.

## Detector Strategy

Initial detector priority:

1. relationship novelty
2. conditional rarity
3. rhythm-of-business deviation
4. robust historical deviation
5. relationship change
6. organization-relative deviation
7. Isolation Forest
8. Random Cut Forest / time-series models
9. sequence and graph methods

A detector score is an anomaly or prioritization signal, not a probability that activity is malicious.

Each finding should explain why it was produced and preserve enough source/time/entity context to pivot back to the SIEM.

## Behavioral State

Important persisted behavioral constructs include:

- actor -> IP
- actor -> application
- actor -> country
- actor -> resource/resource type
- actor -> operation
- service principal/workload identity -> resource
- principal -> subscription/account/project

Relationship state should emphasize behavioral summaries rather than event recreation, for example:

- first seen date
- last seen date
- count over rolling windows
- days observed
- frequency/rarity
- temporal distribution

## Rhythm of Business

Rhythm-of-business modeling is a first-class feature family.

Baselines should eventually operate at multiple scopes:

- entity
- service/workload
- environment/organization

Useful dimensions include:

- hour of day
- weekday
- activity volume
- unique resource/application/IP diversity
- failure ratio
- operation mix

This is intended to distinguish meaningful anomalies from predictable business cycles.

## Evaluation

Known malicious or incident datasets should be used primarily for replay, feature discovery, threshold evaluation, and regression testing rather than immediately training a binary malicious/benign classifier.

Important metrics include:

- rank of known incident activity
- precision@10 / @25 / @50
- recall of known incidents within analyst-reviewable results
- false positives per entity/detector
- time to first signal / lead time
- feature ablation results

Confirmed incident periods should be excludable from baseline/model training.

## Cross-Environment Feature Research

The framework should identify portable properties such as:

- first-seen relationships
- rarity percentile
- relative volume deviations
- activity-time deviation
- diversity changes
- sequence summaries
- relationship/graph changes

Raw customer telemetry and detailed engagement relationship stores must not be combined across engagements. Cross-environment research should operate on explicitly exported evaluation metrics and feature-performance summaries.

## Plan Workflow

Project plans live under:

```text
doc/plan/
├── active/
├── complete/
└── queue/
```

New plans are created in `queue/`.

When work begins, the corresponding plan moves to `active/`.

When implementation and validation are complete, it moves to `complete/`.

The queued plans define the initial implementation sequence for this repository.
