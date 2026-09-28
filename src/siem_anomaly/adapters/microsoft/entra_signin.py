"""Microsoft Entra interactive sign-in adapter."""

from siem_anomaly.adapters.base import MappingAdapter
from siem_anomaly.core.capabilities import Capability, FieldBinding

ENTRA_SIGNIN_ADAPTER = MappingAdapter(
    source_id="microsoft.entra_signin",
    bindings=(
        FieldBinding("timestamp", "TimeGenerated", Capability.TIMESTAMP, "event_time", True),
        FieldBinding(
            "actor",
            "UserPrincipalName",
            Capability.ACTOR,
            "authenticated_principal",
            True,
        ),
        FieldBinding("source_ip", "IPAddress", Capability.SOURCE_IP, "client_origin"),
        FieldBinding(
            "application",
            "AppDisplayName",
            Capability.APPLICATION,
            "client_application",
        ),
        FieldBinding("outcome", "ResultType", Capability.OUTCOME, "authentication_result"),
        FieldBinding("country", "Location", Capability.COUNTRY, "reported_location"),
        FieldBinding("device", "DeviceDetail", Capability.DEVICE, "client_device"),
    ),
)
