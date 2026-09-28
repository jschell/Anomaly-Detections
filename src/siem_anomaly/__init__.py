"""Provider-neutral SIEM anomaly detection and behavioral analytics."""

from siem_anomaly.api import open_engagement
from siem_anomaly.context import EngagementContext

__all__ = ["EngagementContext", "__version__", "open_engagement"]

__version__ = "0.0.0"
