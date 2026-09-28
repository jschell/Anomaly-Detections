"""Canonical entity resolution without raw-event centralization."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AliasBinding:
    source: str
    alias: str
    canonical_id: str
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class CanonicalEntity:
    canonical_id: str
    aliases: tuple[AliasBinding, ...]


class EntityResolver:
    """Explicit alias mapping with confidence; never guesses identity equivalence."""

    def __init__(self, bindings: tuple[AliasBinding, ...] = ()) -> None:
        self._bindings: dict[tuple[str, str], AliasBinding] = {
            (binding.source, binding.alias.casefold()): binding for binding in bindings
        }

    def add(self, binding: AliasBinding) -> None:
        key = (binding.source, binding.alias.casefold())
        existing = self._bindings.get(key)
        if existing is not None and existing.canonical_id != binding.canonical_id:
            raise ValueError(f"Alias already mapped to a different entity: {binding.alias}")
        self._bindings[key] = binding

    def resolve(
        self,
        *,
        source: str,
        alias: str,
        minimum_confidence: float = 0.8,
    ) -> str | None:
        binding = self._bindings.get((source, alias.casefold()))
        if binding is None or binding.confidence < minimum_confidence:
            return None
        return binding.canonical_id

    def entity(self, canonical_id: str) -> CanonicalEntity:
        aliases = tuple(
            binding for binding in self._bindings.values() if binding.canonical_id == canonical_id
        )
        return CanonicalEntity(canonical_id=canonical_id, aliases=aliases)
