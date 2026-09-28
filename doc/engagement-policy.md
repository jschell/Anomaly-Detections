# Engagement Persistence Policy

Each engagement has a versioned `config.yaml` under its anomaly workspace. The file controls engagement-specific evidence lifecycle behavior. It does not weaken framework storage invariants.

The generated file is formatted as JSON, which is valid YAML 1.2, so no additional runtime YAML dependency is required.

Example:

```json
{
  "schema_version": "1",
  "evidence": {
    "investigating": {
      "enabled": true,
      "retention_days": 14
    },
    "incident": {
      "retention": "engagement"
    }
  }
}
```

## Framework invariants

These are not configurable:

- ordinary raw SIEM telemetry cannot be archived
- derived behavioral features/state, baselines, models, findings, evaluation results, and manifests may be persisted
- full events require an explicit analyst evidence-selection action tied to an investigation or incident
- confirmed incident evidence is not removed by temporary-investigation cleanup

## Configuration lifecycle

`open_engagement()` creates a default config only when one does not exist. Existing files are validated and are never silently rewritten.

Unknown fields, unsupported schema versions, invalid retention values, and unsupported incident-retention modes fail validation.

## Investigation evidence

When `evidence.investigating.enabled` is false, full-event evidence cannot be retained while a finding is merely under investigation. Evidence may still be retained after promotion to a confirmed incident.

`retention_days` controls `ctx.workflow.cleanup_expired_investigations()`. Cleanup applies only to active investigations whose workflow metadata is older than the configured retention period. It never scans or deletes confirmed incident directories.

## Inspection

Notebook code can inspect:

```python
ctx.config
ctx.policy.describe()
```

This provides an auditable statement of the effective storage behavior for the engagement.
