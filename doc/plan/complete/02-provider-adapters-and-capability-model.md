# Plan 02 — Provider Adapters and Capability Model

## Goal
Build a provider-neutral semantic and capability layer that supports Microsoft first and AWS, GCP, and Okta without redesign.

## Completed

Implemented and validated:

- provider-neutral actor/resource/event domain records
- typed semantic capability enum and declarative field bindings
- semantic-role metadata and capability completeness
- generic `MappingAdapter`
- adapter registry and field overrides
- Microsoft Entra sign-in, Entra Audit, Azure Activity, and M365 Audit adapters
- Okta System Log adapter
- AWS CloudTrail adapter
- GCP Audit Log adapter
- capability-driven detector discovery
- generic detector modules remain free of provider imports
- generic identity detector discovery demonstrated on Okta
- generic behavioral feature/detector reuse demonstrated on AWS CloudTrail
- adapter-authoring/portability conventions documented in `doc/provider-adapters.md`
- authentication is represented as a canonical capability; richer authentication fields can evolve as feature expansion without changing the capability architecture

## Exit criteria

Satisfied. The same generic capability-driven discovery logic operates across Microsoft and non-Microsoft sources without provider imports in generic detector modules. Later provider-expansion work additionally demonstrates generic behavioral detector reuse on AWS.
