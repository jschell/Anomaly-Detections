"""Cross-source entity resolution and finding correlation."""

from siem_anomaly.correlation.entities import (
    AliasBinding,
    CanonicalEntity,
    EntityResolver,
)
from siem_anomaly.correlation.findings import (
    CorrelatedFindingGroup,
    FindingObservation,
    correlate_findings,
)

__all__ = [
    "AliasBinding",
    "CanonicalEntity",
    "CorrelatedFindingGroup",
    "EntityResolver",
    "FindingObservation",
    "correlate_findings",
]
