from siem_anomaly.adapters.registry import registered_sources


def test_provider_registry_contains_planned_sources() -> None:
    assert {
        "microsoft.entra_signin",
        "microsoft.entra_audit",
        "microsoft.azure_activity",
        "microsoft.m365_audit",
        "okta.system_log",
        "aws.cloudtrail",
        "gcp.audit_log",
    } <= set(registered_sources())
