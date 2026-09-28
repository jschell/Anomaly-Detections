from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import polars as pl

from siem_anomaly.adapters.dataframes import SupportedFrame, to_polars
from siem_anomaly.core import Capability, CapabilityName


_DEFAULT_FIELDS: dict[str, str] = {
    "timestamp": "TimeGenerated",
    "actor": "UserPrincipalName",
    "source_ip": "IPAddress",
    "application": "AppDisplayName",
    "country": "Location",
    "outcome": "ResultType",
    "device": "DeviceDetail",
}

_SEMANTICS: dict[str, tuple[CapabilityName, str]] = {
    "timestamp": (CapabilityName.TIMESTAMP, "event_time"),
    "actor": (CapabilityName.ACTOR, "authenticated_principal"),
    "source_ip": (CapabilityName.SOURCE_IP, "client_origin"),
    "application": (CapabilityName.APPLICATION, "target_application"),
    "country": (CapabilityName.COUNTRY, "source_geography"),
    "outcome": (CapabilityName.OUTCOME, "authentication_result"),
    "device": (CapabilityName.DEVICE, "client_device"),
}


@dataclass(frozen=True, slots=True)
class EntraSigninAdapter:
    source: str = "microsoft.entra_signin"

    def _mapping(self, field_map: Mapping[str, str] | None) -> dict[str, str]:
        mapping = dict(_DEFAULT_FIELDS)
        if field_map:
            unknown = set(field_map) - set(mapping)
            if unknown:
                raise ValueError(f"Unknown canonical fields: {sorted(unknown)}")
            mapping.update(field_map)
        return mapping

    def capabilities(self, frame: SupportedFrame) -> tuple[Capability, ...]:
        df = to_polars(frame)
        names = set(df.columns)
        capabilities: list[Capability] = []
        for canonical, source_field in _DEFAULT_FIELDS.items():
            if source_field not in names:
                continue
            name, role = _SEMANTICS[canonical]
            non_null = df.select(pl.col(source_field).is_not_null().mean()).item()
            capabilities.append(
                Capability(
                    name=name,
                    field=source_field,
                    semantic_role=role,
                    completeness=float(non_null),
                )
            )
        return tuple(capabilities)

    def normalize(
        self,
        frame: SupportedFrame,
        *,
        field_map: Mapping[str, str] | None = None,
    ) -> pl.DataFrame:
        df = to_polars(frame)
        mapping = self._mapping(field_map)
        missing = [source for source in mapping.values() if source not in df.columns]
        if missing:
            raise ValueError(f"Missing source fields: {missing}")
        return df.select([pl.col(source).alias(canonical) for canonical, source in mapping.items()])
