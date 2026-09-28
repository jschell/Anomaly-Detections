"""Microsoft Entra Audit adapter."""

from siem_anomaly.adapters.base import MappingAdapter
from siem_anomaly.core.capabilities import Capability, FieldBinding

ENTRA_AUDIT_ADAPTER = MappingAdapter(
    source_id="microsoft.entra_audit",
    bindings=(
        FieldBinding("timestamp", "TimeGenerated", Capability.TIMESTAMP, "event_time", True),
        FieldBinding("actor", "InitiatedBy.user.userPrincipalName", Capability.ACTOR, "principal", True),
        FieldBinding("action", "ActivityDisplayName", Capability.ACTION, "directory_action"),
        FieldBinding("target", "TargetResources.0.id", Capability.TARGET, "directory_target"),
        FieldBinding("outcome", "Result", Capability.OUTCOME, "operation_result"),
    ),
)
