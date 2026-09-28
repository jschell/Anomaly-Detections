"""Azure Activity adapter."""

from siem_anomaly.adapters.base import MappingAdapter
from siem_anomaly.core.capabilities import Capability, FieldBinding

AZURE_ACTIVITY_ADAPTER = MappingAdapter(
    source_id="microsoft.azure_activity",
    bindings=(
        FieldBinding("timestamp", "TimeGenerated", Capability.TIMESTAMP, "event_time", True),
        FieldBinding("actor", "Caller", Capability.ACTOR, "authenticated_principal", True),
        FieldBinding("source_ip", "CallerIpAddress", Capability.SOURCE_IP, "client_origin"),
        FieldBinding("action", "OperationNameValue", Capability.ACTION, "control_plane_action"),
        FieldBinding("target", "ResourceId", Capability.TARGET, "cloud_resource"),
        FieldBinding("outcome", "ActivityStatusValue", Capability.OUTCOME, "operation_result"),
    ),
)
