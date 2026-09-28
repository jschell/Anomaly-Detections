"""Provider adapter interfaces and generic mapping adapter."""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Protocol, Self

import polars as pl

from siem_anomaly.adapters.frames import TabularData, to_polars
from siem_anomaly.core.capabilities import FieldBinding
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
        frame = to_polars(data)
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
            capabilities=frozenset(binding.capability for binding in present),
            capability_coverage=coverage,
            missing_required_fields=missing,
        )

    def normalize(self, data: TabularData) -> pl.DataFrame:
        frame = to_polars(data)
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
