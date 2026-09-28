# Plan 02 — Provider Adapters and Capability Model

## Goal
Build a provider-neutral semantic and capability layer that supports Microsoft first and AWS, GCP, and Okta later without redesign.

## Progress

Implemented:
- provider-neutral actor/resource/event domain records
- typed semantic capability enum and field bindings
- semantic-role metadata
- per-field capability completeness calculation
- generic declarative `MappingAdapter`
- adapter registry
- Microsoft Entra sign-in adapter
- field override support for notebook queries that rename/project columns
- identical generic mapping/profile logic tested against a synthetic non-Microsoft authentication source
- no provider imports in the generic mapping/capability implementation

Remaining before completion:
- connect capability output to the detector-registry discovery layer introduced by Plan 05
- finalize authentication-context handling when richer Entra fields are introduced
- document adapter-authoring conventions for future Okta/AWS/GCP adapters

## Scope
- Define canonical concepts: timestamp, actor, actor type, action, target/resource, source IP, application/service, outcome, region, device, authentication context.
- Define typed capabilities rather than simple field-presence flags.
- Capture semantic role and completeness where useful.
- Implement Microsoft Entra sign-in adapter first.
- Provide field override support for notebook queries that rename/project fields.
- Preserve provider-specific semantics for provider-specific detectors without leaking them into generic detector code.

## Future adapters
- Microsoft Entra Audit
- Azure Activity
- M365 Audit
- Okta System Log
- AWS CloudTrail/IAM/sign-in
- GCP Audit Logs/IAM

## Exit criteria
The same generic capability-driven detector discovery logic can operate on a canonical Entra sign-in dataframe and a synthetic non-Microsoft dataframe without provider imports in generic detector modules.
