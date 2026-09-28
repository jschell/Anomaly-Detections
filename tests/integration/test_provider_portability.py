from datetime import UTC, datetime
from pathlib import Path

import polars as pl

from siem_anomaly import open_engagement
from siem_anomaly.correlation import AliasBinding, EntityResolver, FindingObservation
from siem_anomaly.core.domain import Finding


def test_okta_reuses_generic_identity_detector_discovery(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    okta = pl.DataFrame(
        {
            "published": ["2026-09-28T10:00:00Z"],
            "actor.alternateId": ["analyst@example.com"],
            "client.ipAddress": ["198.51.100.10"],
            "target.displayName": ["Admin Console"],
            "eventType": ["user.session.start"],
            "outcome.result": ["SUCCESS"],
        }
    )
    available = ctx.discover(okta, source="okta.system_log")
    assert "identity.relationship_novelty" in available
    assert "identity.rhythm_deviation" in available


def test_aws_cloudtrail_reuses_generic_behavioral_features_and_detectors(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    history = pl.DataFrame(
        {
            "eventTime": ["2026-09-20T09:00:00Z", "2026-09-21T09:00:00Z"],
            "userIdentity.arn": [
                "arn:aws:iam::123456789012:user/alice",
                "arn:aws:iam::123456789012:user/alice",
            ],
            "sourceIPAddress": ["192.0.2.10", "192.0.2.10"],
            "eventSource": ["iam.amazonaws.com", "iam.amazonaws.com"],
            "eventName": ["ListRoles", "ListRoles"],
            "resources.0.ARN": [
                "arn:aws:iam::123456789012:role/example",
                "arn:aws:iam::123456789012:role/example",
            ],
            "awsRegion": ["us-west-2", "us-west-2"],
            "errorCode": [None, None],
        }
    )
    ctx.derive(
        history,
        source="aws.cloudtrail",
        query_id="aws-history",
    )

    current = pl.DataFrame(
        {
            "eventTime": ["2026-09-28T03:00:00Z"],
            "userIdentity.arn": ["arn:aws:iam::123456789012:user/alice"],
            "sourceIPAddress": ["198.51.100.77"],
            "eventSource": ["iam.amazonaws.com"],
            "eventName": ["CreateAccessKey"],
            "resources.0.ARN": ["arn:aws:iam::123456789012:user/alice"],
            "awsRegion": ["us-west-2"],
            "errorCode": [None],
        }
    )
    findings = ctx.detect(current, source="aws.cloudtrail", persist=False)
    ids = {finding.detector_id for finding in findings}
    assert "identity.relationship_novelty" in ids
    assert "identity.relationship_change" in ids


def test_cross_source_findings_correlate_via_explicit_canonical_identity(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    resolver = EntityResolver(
        (
            AliasBinding(
                source="microsoft.entra_signin",
                alias="alice@example.com",
                canonical_id="person:alice",
            ),
            AliasBinding(
                source="okta.system_log",
                alias="alice@example.com",
                canonical_id="person:alice",
            ),
        )
    )
    entra = Finding(
        finding_id="entra-f1",
        detector_id="identity.relationship_novelty",
        source="microsoft.entra_signin",
        start=datetime(2026, 9, 28, 10, tzinfo=UTC),
        end=datetime(2026, 9, 28, 10, 5, tzinfo=UTC),
        score=1.0,
        entity="alice@example.com",
    )
    okta = Finding(
        finding_id="okta-f1",
        detector_id="identity.relationship_change",
        source="okta.system_log",
        start=datetime(2026, 9, 28, 10, 10, tzinfo=UTC),
        end=datetime(2026, 9, 28, 10, 12, tzinfo=UTC),
        score=0.9,
        entity="alice@example.com",
    )
    groups = ctx.correlate(
        (
            FindingObservation(entra, source_ip="198.51.100.8"),
            FindingObservation(okta, source_ip="198.51.100.8"),
        ),
        resolver=resolver,
    )
    assert len(groups) == 1
    assert groups[0].canonical_entities == ("person:alice",)
    assert groups[0].sources == ("microsoft.entra_signin", "okta.system_log")
    assert "source_ip:198.51.100.8" in groups[0].shared_dimensions
