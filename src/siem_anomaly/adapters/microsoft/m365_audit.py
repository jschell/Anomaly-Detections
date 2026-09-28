"""Microsoft 365 Unified Audit adapter."""

from siem_anomaly.adapters.base import MappingAdapter
from siem_anomaly.core.capabilities import Capability, FieldBinding

M365_AUDIT_ADAPTER = MappingAdapter(
    source_id="microsoft.m365_audit",
    bindings=(
        FieldBinding("timestamp", "CreationTime", Capability.TIMESTAMP, "event_time", True),
        FieldBinding("actor", "UserId", Capability.ACTOR, "authenticated_principal", True),
        FieldBinding("source_ip", "ClientIP", Capability.SOURCE_IP, "client_origin"),
        FieldBinding("application", "Workload", Capability.APPLICATION, "saas_service"),
        FieldBinding("action", "Operation", Capability.ACTION, "saas_action"),
        FieldBinding("target", "ObjectId", Capability.TARGET, "saas_object"),
        FieldBinding("outcome", "ResultStatus", Capability.OUTCOME, "operation_result"),
    ),
)
