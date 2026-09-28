"""Typed profiling results returned to notebooks."""

from dataclasses import dataclass

from siem_anomaly.core.capabilities import Capability


@dataclass(frozen=True, slots=True)
class DataProfile:
    source: str
    row_count: int
    columns: tuple[str, ...]
    capabilities: frozenset[Capability]
    missing_required_fields: tuple[str, ...]
