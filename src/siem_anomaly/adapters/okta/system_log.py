"""Okta System Log adapter."""

from siem_anomaly.adapters.base import MappingAdapter
from siem_anomaly.core.capabilities import Capability, FieldBinding

OKTA_SYSTEM_LOG_ADAPTER = MappingAdapter(
    source_id="okta.system_log",
    bindings=(
        FieldBinding("timestamp", "published", Capability.TIMESTAMP, "event_time", True),
        FieldBinding("actor", "actor.alternateId", Capability.ACTOR, "authenticated_principal", True),
        FieldBinding("source_ip", "client.ipAddress", Capability.SOURCE_IP, "client_origin"),
        FieldBinding("application", "target.displayName", Capability.APPLICATION, "target_application"),
        FieldBinding("action", "eventType", Capability.ACTION, "event_action"),
        FieldBinding("outcome", "outcome.result", Capability.OUTCOME, "event_result"),
    ),
)
