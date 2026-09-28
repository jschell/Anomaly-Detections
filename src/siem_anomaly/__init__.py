"""Provider-neutral SIEM anomaly detection and behavioral analytics."""

from .engagement import EngagementContext, open_engagement

__all__ = ["EngagementContext", "__version__", "open_engagement"]

__version__ = "0.1.0"
