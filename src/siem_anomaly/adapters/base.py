from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol

import polars as pl

from siem_anomaly.adapters.dataframes import SupportedFrame
from siem_anomaly.core import Capability


class SourceAdapter(Protocol):
    source: str

    def capabilities(self, frame: SupportedFrame) -> tuple[Capability, ...]: ...

    def normalize(
        self,
        frame: SupportedFrame,
        *,
        field_map: Mapping[str, str] | None = None,
    ) -> pl.DataFrame: ...


@dataclass(frozen=True, slots=True)
class SchemaProfile:
    source: str
    rows: int
    columns: tuple[str, ...]
    capabilities: tuple[Capability, ...]
