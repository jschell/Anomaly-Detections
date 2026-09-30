"""Provider adapter interfaces and generic mapping adapter."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Protocol, Self

import polars as pl

from siem_anomaly.adapters.frames import TabularData, to_polars
from siem_anomaly.core.capabilities import Capability, FieldBinding
from siem_anomaly.core.network import normalize_network_fields
from siem_anomaly.core.profile import CapabilityCoverage, DataProfile


class SourceAdapter(Protocol):
    @property
    def source_id(self) -> str: ...

    @property
    def bindings(self) -> tuple[FieldBinding, ...]: ...

    def normalize(self, data: TabularData) -> pl.DataFrame: ...

    def profile(self, data: TabularData) -> DataProfile: ...


@dataclass(frozen=True, slots=True)
class MappingAdapter:
    """Declarative adapter for sources expressible as field mappings."""

    source_id: str
    bindings: tuple[FieldBinding, ...]

    def with_enrichment(self, fields: Mapping[str, str]) -> Self:
        """Bind optional, already enriched source columns without changing the base adapter."""
        allowed = {"asn": Capability.ASN, "network_trait": Capability.NETWORK_TRAIT}
        unknown = set(fields) - set(allowed)
        if unknown:
            raise KeyError(f"Unknown enrichment field(s): {', '.join(sorted(unknown))}")
        if len(set(fields.values())) != len(fields):
            raise ValueError("Each enrichment field must map to a distinct source column")
        bindings = tuple(
            binding for binding in self.bindings if binding.canonical_name not in fields
        )
        return replace(
            self,
            bindings=bindings
            + tuple(
                FieldBinding(name, source, allowed[name], "client_network_enrichment")
                for name, source in fields.items()
            ),
        )

    def with_overrides(self, overrides: Mapping[str, str]) -> Self:
        """Return an adapter with canonical-field source mappings overridden."""
        known = {binding.canonical_name for binding in self.bindings}
        unknown = set(overrides) - known
        if unknown:
            fields = ", ".join(sorted(unknown))
            raise KeyError(f"Unknown canonical field override(s): {fields}")
        return replace(
            self,
            bindings=tuple(
                replace(
                    binding,
                    source_field=overrides.get(binding.canonical_name, binding.source_field),
                )
                for binding in self.bindings
            ),
        )

    def profile(self, data: TabularData) -> DataProfile:
        frame = normalize_network_fields(to_polars(data), self.bindings)
        columns = frozenset(frame.columns)
        present = tuple(binding for binding in self.bindings if binding.source_field in columns)
        missing = tuple(
            binding.source_field
            for binding in self.bindings
            if binding.required and binding.source_field not in columns
        )
        coverage = tuple(
            CapabilityCoverage(
                capability=binding.capability,
                canonical_name=binding.canonical_name,
                source_field=binding.source_field,
                semantic_role=binding.semantic_role,
                completeness=(
                    0.0
                    if frame.height == 0
                    else 1.0 - (frame.get_column(binding.source_field).null_count() / frame.height)
                ),
            )
            for binding in present
        )
        return DataProfile(
            source=self.source_id,
            row_count=frame.height,
            columns=tuple(frame.columns),
            capabilities=frozenset(
                binding.capability
                for binding, item in zip(present, coverage, strict=True)
                if item.completeness > 0
                or binding.capability not in {Capability.ASN, Capability.NETWORK_TRAIT}
            ),
            capability_coverage=coverage,
            missing_required_fields=missing,
        )

    def normalize(self, data: TabularData) -> pl.DataFrame:
        frame = normalize_network_fields(to_polars(data), self.bindings)
        profile = self.profile(frame)
        if profile.missing_required_fields:
            missing = ", ".join(profile.missing_required_fields)
            raise ValueError(f"Missing required source fields for {self.source_id}: {missing}")
        expressions = [
            pl.col(binding.source_field).alias(binding.canonical_name)
            for binding in self.bindings
            if binding.source_field in frame.columns
        ]
        return frame.select(expressions)
