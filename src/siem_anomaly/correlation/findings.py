"""Correlate derived findings across sources, never source event archives."""

import hashlib
from dataclasses import dataclass
from datetime import timedelta

from siem_anomaly.core.domain import Finding
from siem_anomaly.correlation.entities import EntityResolver


@dataclass(frozen=True, slots=True)
class FindingObservation:
    finding: Finding
    source_ip: str | None = None
    application: str | None = None
    resource: str | None = None


@dataclass(frozen=True, slots=True)
class CorrelatedFindingGroup:
    group_id: str
    finding_ids: tuple[str, ...]
    sources: tuple[str, ...]
    canonical_entities: tuple[str, ...]
    shared_dimensions: tuple[str, ...]
    start: str
    end: str


def _canonical_entity(observation: FindingObservation, resolver: EntityResolver) -> str | None:
    entity = observation.finding.entity
    if entity is None:
        return None
    resolved = resolver.resolve(source=observation.finding.source, alias=entity)
    return resolved or f"{observation.finding.source}:{entity.casefold()}"


def _shared_dimensions(left: FindingObservation, right: FindingObservation) -> tuple[str, ...]:
    dimensions: list[str] = []
    for name in ("source_ip", "application", "resource"):
        left_value = getattr(left, name)
        right_value = getattr(right, name)
        if left_value is not None and left_value == right_value:
            dimensions.append(f"{name}:{left_value}")
    return tuple(dimensions)


def correlate_findings(
    observations: tuple[FindingObservation, ...],
    *,
    resolver: EntityResolver,
    window: timedelta = timedelta(hours=1),
) -> tuple[CorrelatedFindingGroup, ...]:
    """Cluster findings sharing canonical identity or derived dimensions in time."""
    unused = set(range(len(observations)))
    groups: list[CorrelatedFindingGroup] = []

    while unused:
        seed_index = min(unused)
        unused.remove(seed_index)
        members = {seed_index}
        changed = True
        while changed:
            changed = False
            for candidate_index in tuple(unused):
                candidate = observations[candidate_index]
                for member_index in members:
                    member = observations[member_index]
                    distance = min(
                        abs(candidate.finding.start - member.finding.end),
                        abs(member.finding.start - candidate.finding.end),
                    )
                    if distance > window:
                        continue
                    candidate_entity = _canonical_entity(candidate, resolver)
                    member_entity = _canonical_entity(member, resolver)
                    same_entity = candidate_entity is not None and candidate_entity == member_entity
                    shared = _shared_dimensions(candidate, member)
                    if same_entity or shared:
                        members.add(candidate_index)
                        unused.remove(candidate_index)
                        changed = True
                        break

        if len(members) < 2:
            continue
        selected = [observations[index] for index in sorted(members)]
        finding_ids = tuple(sorted(item.finding.finding_id for item in selected))
        sources = tuple(sorted({item.finding.source for item in selected}))
        entities = tuple(
            sorted(
                {
                    entity
                    for item in selected
                    if (entity := _canonical_entity(item, resolver)) is not None
                }
            )
        )
        shared: set[str] = set()
        for left_index, left in enumerate(selected):
            for right in selected[left_index + 1 :]:
                shared.update(_shared_dimensions(left, right))
        start = min(item.finding.start for item in selected)
        end = max(item.finding.end for item in selected)
        digest = hashlib.sha256("|".join(finding_ids).encode()).hexdigest()[:20]
        groups.append(
            CorrelatedFindingGroup(
                group_id=digest,
                finding_ids=finding_ids,
                sources=sources,
                canonical_entities=entities,
                shared_dimensions=tuple(sorted(shared)),
                start=start.isoformat(),
                end=end.isoformat(),
            )
        )
    return tuple(groups)
