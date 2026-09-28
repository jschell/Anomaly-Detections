# Plan 03 — Derived Features, State, and Rhythm of Business

## Goal
Create the persistent behavioral history that replaces any need for a local raw-event archive.

## Completed
Implemented and validated:
- actor-hour and actor-day features
- service-hour, resource-hour, operation-hour, and environment-hour feature families
- actor → IP/application/country/resource/operation relationship state
- first/last seen date, event counts, days seen, and rarity score
- actor and environment weekday/hour rhythm baselines
- engagement-local Parquet persistence only for derived state
- repeated query partitions overwrite by stable query ID rather than duplicate
- integration tests proving historical state supports later novelty, rarity, rhythm, and volume detection without retained ordinary raw events

## Scope
### Feature stores
- actor-hour
- actor-day
- service-hour
- resource-hour
- operation-hour

### Relationship state
- actor → IP
- actor → application
- actor → country
- actor → resource
- actor → operation

### Rhythm of business
Entity and environment weekday/hour baselines are persisted from derived feature history.

## Exit criteria
Satisfied. Historical SIEM windows can be streamed through `ctx.derive()` into derived Parquet state; detectors subsequently operate from that state without a raw-event archive.
