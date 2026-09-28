"""Provider adapter interfaces and generic mapping adapter."""

from dataclasses import dataclass
from typing import Protocol

import polars as pl

from siem_anomaly.adapters.frames import TabularData, to_polars
from siem_anomaly.core.capabilities import FieldBinding
from siem_anomaly.core.profile import DataProfile


class SourceAdapter(Protocol):
    source_id: str
    bindings: tuple[FieldBinding, ...]

    def normalize(self, data: TabularData) -> pl.DataFrame: ...

    def profile(self, data: TabularData) -> DataProfile: ...


@dataclass(frozen=True, slots=True)
class MappingAdapter:
    """Declarative adapter for sources expressible as field mappings."""

    source_id: str
    bindings: tuple[FieldBinding, ...]

    def profile(self, data: TabularData) -> DataProfile:
        frame = to_polars(data)
        columns = frozenset(frame.columns)
        present = tuple(binding for binding in self.bindings if binding.source_field in columns)
        missing = tuple(
            binding.source_field
            for binding in self.bindings
            if binding.required and binding.source_field not in columns
        )
        return DataProfile(
            source=self.source_id,
            row_count=frame.height,
            columns=tuple(frame.columns),
            capabilities=frozenset(binding.capability for binding in present),
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
