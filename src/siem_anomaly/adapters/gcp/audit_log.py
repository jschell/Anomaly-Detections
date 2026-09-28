"""Google Cloud Audit Logs adapter."""

from siem_anomaly.adapters.base import MappingAdapter
from siem_anomaly.core.capabilities import Capability, FieldBinding

GCP_AUDIT_LOG_ADAPTER = MappingAdapter(
    source_id="gcp.audit_log",
    bindings=(
        FieldBinding("timestamp", "timestamp", Capability.TIMESTAMP, "event_time", True),
        FieldBinding(
            "actor",
            "protoPayload.authenticationInfo.principalEmail",
            Capability.ACTOR,
            "authenticated_principal",
            True,
        ),
        FieldBinding(
            "source_ip",
            "protoPayload.requestMetadata.callerIp",
            Capability.SOURCE_IP,
            "client_origin",
        ),
        FieldBinding(
            "application",
            "protoPayload.serviceName",
            Capability.APPLICATION,
            "cloud_service",
        ),
        FieldBinding("action", "protoPayload.methodName", Capability.ACTION, "api_action"),
        FieldBinding("target", "resourceName", Capability.TARGET, "cloud_resource"),
        FieldBinding("region", "resource.labels.location", Capability.REGION, "cloud_region"),
        FieldBinding("outcome", "protoPayload.status.code", Capability.OUTCOME, "api_result"),
    ),
)
