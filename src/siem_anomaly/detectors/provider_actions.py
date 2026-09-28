"""Provider-specific notable control-plane action packs.

These are prioritization signals, not claims that an action is malicious.
"""

import hashlib
from datetime import UTC, datetime

import polars as pl

from siem_anomaly.core.domain import Finding

_PROVIDER_ACTIONS: dict[str, frozenset[str]] = {
    "microsoft.entra_audit": frozenset(
        {
            "Add member to role",
            "Add eligible member to role",
            "Update Conditional Access policy",
            "Add service principal credentials",
        }
    ),
    "microsoft.azure_activity": frozenset(
        {
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Authorization/policyAssignments/write",
        }
    ),
    "microsoft.m365_audit": frozenset(
        {
            "New-InboxRule",
            "Set-InboxRule",
            "Add-MailboxPermission",
        }
    ),
    "okta.system_log": frozenset(
        {
            "user.mfa.factor.reset_all",
            "policy.lifecycle.update",
            "application.lifecycle.create",
        }
    ),
    "aws.cloudtrail": frozenset(
        {
            "CreateAccessKey",
            "AttachUserPolicy",
            "AttachRolePolicy",
            "UpdateAssumeRolePolicy",
            "StopLogging",
        }
    ),
    "gcp.audit_log": frozenset(
        {
            "google.iam.admin.v1.CreateServiceAccountKey",
            "SetIamPolicy",
        }
    ),
}


def notable_actions(source: str) -> frozenset[str]:
    return _PROVIDER_ACTIONS.get(source, frozenset())


def detect_provider_actions(frame: pl.DataFrame, *, source: str) -> tuple[Finding, ...]:
    """Emit explainable findings for configured notable provider actions."""
    actions = notable_actions(source)
    if not actions or "action" not in frame.columns or frame.is_empty():
        return ()

    with_time = frame.with_columns(
        pl.col("timestamp")
        .cast(pl.Utf8)
        .str.to_datetime(strict=False, time_zone="UTC")
        .alias("_ts")
    ).drop_nulls(["_ts", "action"])

    findings: list[Finding] = []
    for row in with_time.filter(pl.col("action").is_in(actions)).iter_rows(named=True):
        action = str(row["action"])
        actor = str(row["actor"]) if row.get("actor") is not None else None
        timestamp = _as_utc(row["_ts"])
        detail = f"{source}|{actor}|{action}|{timestamp.isoformat()}"
        finding_id = hashlib.sha256(detail.encode()).hexdigest()[:20]
        findings.append(
            Finding(
                finding_id=finding_id,
                detector_id=f"{source}.notable_action",
                source=source,
                start=timestamp,
                end=timestamp,
                score=0.75,
                entity=actor,
                reason_codes=("provider_notable_action",),
                reasons=(f"provider-specific notable action observed: {action}",),
            )
        )
    return tuple(findings)


def _as_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
