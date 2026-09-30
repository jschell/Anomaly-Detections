"""Canonical validation for optional, transient network enrichment."""

import re
from collections.abc import Iterable
from typing import cast

import polars as pl

from siem_anomaly.core.capabilities import FieldBinding

TRAITS = frozenset({"hosting", "cdn", "proxy", "vpn"})


def asn_value(value: object) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    raw = str(value).strip().upper()
    if raw.startswith("AS"):
        raw = raw[2:]
    if not re.fullmatch(r"[0-9]+", raw):
        return None
    number = int(raw)
    return str(number) if 0 < number <= 4_294_967_295 else None


def trait_value(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        values = re.split(r"[,|]", value)
    elif isinstance(value, (list, tuple, set)):
        values = [str(item) for item in cast("Iterable[object]", value)]
    else:
        return None
    normalized = {item.strip().lower() for item in values if item.strip().lower() in TRAITS}
    return ",".join(sorted(normalized)) or None


def normalize_network_fields(frame: pl.DataFrame, bindings: Iterable[FieldBinding]) -> pl.DataFrame:
    converters = {"asn": asn_value, "network_trait": trait_value}
    for binding in bindings:
        if binding.canonical_name in converters and binding.source_field in frame.columns:
            converter = converters[binding.canonical_name]
            frame = frame.with_columns(
                pl.Series(
                    binding.source_field,
                    [converter(value) for value in frame[binding.source_field].to_list()],
                    dtype=pl.String,
                )
            )
    return frame
