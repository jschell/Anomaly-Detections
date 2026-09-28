# Plan 03 — Derived Features, State, and Rhythm of Business

## Goal
Create the persistent behavioral history that replaces any need for a local raw-event archive.

## Scope
### Feature stores
Start with:
- actor-hour
- actor-day
- service-hour
- resource-hour
- operation-hour

Candidate features include:
- event/success/failure counts
- failure ratios
- unique IP/application/resource/operation counts
- novelty counts
- rarity counts/scores
- diversity measures
- historical percentiles

### Relationship state
Initial relationships:
- actor → IP
- actor → application
- actor → country
- actor → resource/resource type
- actor → operation
- workload identity → resource
- principal → subscription/account/project

Store behavioral summaries such as first/last seen date, counts over rolling windows, days seen, and rarity. Avoid exact per-event history unless explicitly required.

### Rhythm of business
Create entity, service, and environment baselines by hour-of-day and weekday.

## Exit criteria
A 90-day SIEM backfill can be streamed through notebook queries to build derived Parquet state, after which novelty, rarity, and rhythm queries can operate without retained ordinary raw events.
