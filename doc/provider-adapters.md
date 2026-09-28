# Provider Adapter Guide

Provider adapters map source-specific columns into provider-neutral semantic fields. Generic features and detectors consume canonical fields and must not import provider modules.

## Built-in sources

- `microsoft.entra_signin`
- `microsoft.entra_audit`
- `microsoft.azure_activity`
- `microsoft.m365_audit`
- `okta.system_log`
- `aws.cloudtrail`
- `gcp.audit_log`

## Adapter contract

Adapters should expose a stable `source_id` and declarative `FieldBinding` entries. At minimum, reusable behavioral analysis generally needs `timestamp` and `actor`; additional capabilities such as `source_ip`, `application`, `action`, `target`, `region`, and `outcome` enable more feature families and detectors.

Provider-specific action packs may emit notable-action findings, but these are prioritization signals rather than assertions that an action is malicious.

Field overrides remain available for notebook queries that project or rename source columns.

## Portability rule

Generic detectors depend on semantic capabilities. Provider-specific modules may map fields and define specialized action sets, but generic detector code must not import those provider modules.
