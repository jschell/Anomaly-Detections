# Plan 02 — Provider Adapters and Capability Model

## Goal
Build a provider-neutral semantic and capability layer that supports Microsoft first and AWS, GCP, and Okta later without redesign.

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
