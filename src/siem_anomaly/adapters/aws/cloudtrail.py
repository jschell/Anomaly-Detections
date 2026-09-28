"""AWS CloudTrail adapter."""

from siem_anomaly.adapters.base import MappingAdapter
from siem_anomaly.core.capabilities import Capability, FieldBinding

AWS_CLOUDTRAIL_ADAPTER = MappingAdapter(
    source_id="aws.cloudtrail",
    bindings=(
        FieldBinding("timestamp", "eventTime", Capability.TIMESTAMP, "event_time", True),
        FieldBinding(
            "actor",
            "userIdentity.arn",
            Capability.ACTOR,
            "authenticated_principal",
            True,
        ),
        FieldBinding("source_ip", "sourceIPAddress", Capability.SOURCE_IP, "client_origin"),
        FieldBinding("application", "eventSource", Capability.APPLICATION, "cloud_service"),
        FieldBinding("action", "eventName", Capability.ACTION, "api_action"),
        FieldBinding("target", "resources.0.ARN", Capability.TARGET, "cloud_resource"),
        FieldBinding("region", "awsRegion", Capability.REGION, "cloud_region"),
        FieldBinding("outcome", "errorCode", Capability.OUTCOME, "api_result"),
    ),
)
