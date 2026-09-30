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

## Optional enrichment bindings

`MappingAdapter.with_enrichment({"asn": "source_column", "network_trait": "trait_column"})` creates an immutable adapter variant for already enriched query results. `EngagementContext` exposes the same mapping as `enrichment_fields` across profile, normalize, discover, derive, and detect. Existing `with_overrides()` remains for fields already bound in an adapter. A wholly null or invalid enrichment column does not enable its detectors.

The canonical ASN is a decimal string in the public 32-bit range. Network traits are a controlled multi-valued set (`hosting`, `cdn`, `proxy`, `vpn`). Unsupported values become null. A consuming notebook should attach enrichment before passing a transient frame into this package and identify its dataset version. Manifests record source, version, and field coverage; stored behavior remains aggregate or relationship state. One feature version must remain tied to one source and enrichment snapshot. Backfill under a new version when the source or snapshot changes.

## Portability rule

Generic detectors depend on semantic capabilities. Provider-specific modules may map fields and define specialized action sets, but generic detector code must not import those provider modules.
