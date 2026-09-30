# Plan 11 — Optional Network Enrichment and Behavioral Detection

## Goal

Allow the anomaly framework to consume optional ASN and network classification enrichment from in-memory source results, derive versioned behavioral state, and produce explainable findings when sufficient historical coverage exists. Keep the package independent of any enrichment vendor or notebook repository.

## Scope and boundaries

- The consuming notebook or source pipeline performs SIEM queries and any external IP enrichment. This package accepts fields already present in the transient input; it does not download datasets or call an enrichment service.
- Ordinary raw events remain in the SIEM. Persist only permitted aggregates, relationship state, findings, coverage, and provenance. Full event evidence follows the existing explicit investigation/incident workflow.
- Do not include customer data, engagement names, observed IPs/ASNs, screenshots, or results from a particular replay in source, fixtures, examples, or plan acceptance criteria.
- A consuming notebook bridge may require a separate change. Document the package contract here; do not add a path or implementation belonging to another repository.

## Design decisions to make before implementation

1. Define the canonical ASN representation and validation, including unknown, private/reserved, malformed, and changed IP-to-ASN assignments. Preserve the distinction between an ASN observation and an actor identity.
2. Define network classification as a controlled, possibly multi-valued taxonomy. Distinguish hosting, CDN, proxy, VPN, and unknown instead of treating them as interchangeable or inherently malicious. Specify how conflicting or changed classifications are represented.
3. Define field-level provenance: enrichment provider/dataset, version or snapshot time, observed/enriched time where available, and coverage. Decide which provenance is needed in manifests versus derived state without retaining an event-level enrichment archive.
4. Specify minimum baseline age and coverage, lookback, first-observation behavior, null handling, thresholds, and score interpretation for each detector. A score is an anomaly prioritization signal, not a malicious probability.
5. Decide whether optional enrichment enters through additional adapter bindings, a validated attachment API, or both. The current `MappingAdapter.with_overrides()` only overrides fields already in `bindings`; adding an unknown `asn` or `network_trait` key currently fails. Ensure profile, normalize, discover, derive, and detect use the same resolved mapping.

## Work

### 1. Capability and adapter contract

- Add optional ASN and network classification capabilities and canonical fields with typed validation.
- Bind a native source field only after verifying its semantics for that adapter. Provide a provider-neutral way to attach pre-enriched columns for other sources, without provider imports in generic detectors.
- Report usable capability coverage, including non-null/valid values and classification provenance; a present but wholly null column must not enable a detector.
- Define behavior for missing enrichment, conflicting inputs, malformed values, and duplicate canonical mappings. Existing un-enriched inputs must continue to work.

### 2. Versioned feature derivation and persistence

- Derive actor/ASN relationship summaries, actor/network classification summaries, and unique ASN counts per actor-hour (and any required denominator or peer aggregate). Do not persist one row per original event.
- Add the new aggregates and state to `DerivedBatch` and `FeatureRepository`, preserving engagement isolation and idempotent/repeatable derivation behavior.
- Use a new feature version or explicit migration contract for the changed schema. Do not present older `identity-v1` history as complete enrichment history.
- Record enrichment and feature coverage in manifests so a detector can distinguish missing history from genuinely novel behavior. Re-query source data through the consuming notebook for backfill when needed; never reconstruct missing history from an ordinary raw-event cache.
- Register the actual feature IDs, versions, consumers, maturity, storage class, and portability expectation in the feature catalog. Treat initial portability claims as hypotheses until evaluated.

### 3. Explainable detectors

Implement and register, subject to the design decisions above:

- `identity.asn_novelty`: an actor/ASN pair absent from eligible historical state.
- `identity.asn_change`: an established actor uses a previously unseen ASN; define how this differs from or refines ASN novelty to avoid redundant analyst alerts.
- `identity.asn_diversity`: an actor-hour's distinct ASN count exceeds a sufficiently populated historical or peer baseline, with an explicit denominator and threshold.
- `identity.network_trait_novelty` (name may be refined): an actor's classified network property is new relative to eligible history. Explain the specific classification and its provenance; do not label all hosting/CDN/proxy traffic suspicious.

For each detector, define reason codes, entity/window, score calculation, minimum coverage, insufficient-history suppression, and handling of changed taxonomy or enrichment version. Avoid fixed scores copied from source-IP detectors without calibration. Ensure registration governs actual execution in `EngagementContext.detect()`; discovery and emitted findings must agree.

### 4. Integration contract and documentation

- Show a runnable package-side example using synthetic, pre-enriched data and the supported adapter/attachment API.
- Document the consuming notebook's responsibility for enrichment and field mapping without embedding notebook-specific code or paths in this repository.
- Update README and architecture/capability documentation when the public API or storage schema changes. Document backfill, missing coverage, and classification limitations.

### 5. Validation

Use synthetic fixtures and approved de-identified evaluation summaries only:

- Unit tests for ASN normalization, multi-valued classification, nulls, conflicts, timestamp handling, and deterministic feature calculations.
- Integration tests for native and attached fields through profile, normalize, discover, derive, persist, reload, and detect; absent or unusable enrichment must produce no enrichment-dependent findings.
- Storage tests proving only aggregate/relationship state is persisted, repeat ingestion does not inflate history, engagement state stays isolated, and older feature versions are not silently mixed.
- Temporal tests proving the scored window cannot enter its own baseline and future observations cannot affect earlier findings. Cover insufficient history, incomplete backfill, and enrichment/taxonomy version changes.
- Synthetic behavior and known-incident replay tests comparing incremental recall/rank contribution, false positives, and detector ablation with the existing detectors. Do not require an improvement in any single environment or hard-code a cohort rank.
- Run `uv sync --all-extras --dev`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, and `uv run pytest`.

## Exit criteria

- Enriched and un-enriched inputs work through the public API, with capability discovery matching the detectors that can actually run.
- New derived data is versioned, coverage-aware, engagement-scoped, and compliant with the raw telemetry policy.
- Four detectors have documented eligibility and explanations, with no future-data leakage or unsupported claims about maliciousness.
- Synthetic tests and replay evaluation report incremental value and false-positive costs; any unsupported detector remains disabled or experimental with the reason documented.
- Documentation and all repository validation gates pass before moving this plan to `complete/`.
