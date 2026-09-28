"""Small public API intended for notebook consumers."""

from pathlib import Path

from siem_anomaly.context import EngagementContext


def open_engagement(path: str | Path) -> EngagementContext:
    """Open or initialize an engagement-local anomaly workspace."""
    return EngagementContext.open(path)
