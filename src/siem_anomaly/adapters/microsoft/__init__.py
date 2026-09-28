"""Microsoft source adapters."""

from siem_anomaly.adapters.microsoft.azure_activity import AZURE_ACTIVITY_ADAPTER
from siem_anomaly.adapters.microsoft.entra_audit import ENTRA_AUDIT_ADAPTER
from siem_anomaly.adapters.microsoft.entra_signin import ENTRA_SIGNIN_ADAPTER
from siem_anomaly.adapters.microsoft.m365_audit import M365_AUDIT_ADAPTER

__all__ = [
    "AZURE_ACTIVITY_ADAPTER",
    "ENTRA_AUDIT_ADAPTER",
    "ENTRA_SIGNIN_ADAPTER",
    "M365_AUDIT_ADAPTER",
]
