"""Manifest records for reproducible derived-data generation."""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CoverageWindow:
    start: datetime
    end: datetime


@dataclass(frozen=True, slots=True)
class ManifestRecord:
    feature_set: str
    feature_version: str
    source: str
    query_id: str
    query_hash: str
    start: datetime
    end: datetime
    source_rows: int
    derived_rows: int
    adapter_version: str
    framework_version: str
    overlap_strategy: str = "idempotent_query_partition_then_rebuild"

    @classmethod
    def create(
        cls,
        *,
        feature_set: str,
        feature_version: str,
        source: str,
        query_id: str,
        start: datetime,
        end: datetime,
        source_rows: int,
        derived_rows: int,
        adapter_version: str,
        framework_version: str,
    ) -> "ManifestRecord":
        query_hash = hashlib.sha256(query_id.encode()).hexdigest()[:16]
        return cls(
            feature_set=feature_set,
            feature_version=feature_version,
            source=source,
            query_id=query_id,
            query_hash=query_hash,
            start=start.astimezone(UTC),
            end=end.astimezone(UTC),
            source_rows=source_rows,
            derived_rows=derived_rows,
            adapter_version=adapter_version,
            framework_version=framework_version,
        )


class ManifestStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def write(self, record: ManifestRecord) -> Path:
        destination = self.root / f"{record.feature_set}-{record.query_hash}.json"
        payload = asdict(record)
        payload["start"] = record.start.isoformat()
        payload["end"] = record.end.isoformat()
        destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return destination

    def records(
        self,
        *,
        feature_set: str | None = None,
        feature_version: str | None = None,
    ) -> tuple[ManifestRecord, ...]:
        records: list[ManifestRecord] = []
        for path in sorted(self.root.glob("*.json")):
            payload: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
            record = ManifestRecord(
                feature_set=str(payload["feature_set"]),
                feature_version=str(payload["feature_version"]),
                source=str(payload["source"]),
                query_id=str(payload["query_id"]),
                query_hash=str(payload["query_hash"]),
                start=datetime.fromisoformat(str(payload["start"])),
                end=datetime.fromisoformat(str(payload["end"])),
                source_rows=int(str(payload["source_rows"])),
                derived_rows=int(str(payload["derived_rows"])),
                adapter_version=str(payload["adapter_version"]),
                framework_version=str(payload["framework_version"]),
                overlap_strategy=str(
                    payload.get(
                        "overlap_strategy",
                        "idempotent_query_partition_then_rebuild",
                    )
                ),
            )
            if feature_set is not None and record.feature_set != feature_set:
                continue
            if feature_version is not None and record.feature_version != feature_version:
                continue
            records.append(record)
        return tuple(records)

    def coverage(
        self,
        *,
        feature_set: str,
        feature_version: str,
    ) -> tuple[CoverageWindow, ...]:
        intervals = sorted(
            (
                CoverageWindow(record.start, record.end)
                for record in self.records(
                    feature_set=feature_set,
                    feature_version=feature_version,
                )
            ),
            key=lambda item: item.start,
        )
        merged: list[CoverageWindow] = []
        for interval in intervals:
            if not merged or interval.start > merged[-1].end:
                merged.append(interval)
                continue
            merged[-1] = CoverageWindow(
                merged[-1].start,
                max(merged[-1].end, interval.end),
            )
        return tuple(merged)

    def missing_windows(
        self,
        *,
        feature_set: str,
        feature_version: str,
        start: datetime,
        end: datetime,
    ) -> tuple[CoverageWindow, ...]:
        cursor = start.astimezone(UTC)
        requested_end = end.astimezone(UTC)
        missing: list[CoverageWindow] = []
        for covered in self.coverage(
            feature_set=feature_set,
            feature_version=feature_version,
        ):
            if covered.end <= cursor or covered.start >= requested_end:
                continue
            if covered.start > cursor:
                missing.append(CoverageWindow(cursor, min(covered.start, requested_end)))
            cursor = max(cursor, covered.end)
            if cursor >= requested_end:
                break
        if cursor < requested_end:
            missing.append(CoverageWindow(cursor, requested_end))
        return tuple(window for window in missing if window.end - window.start > timedelta(0))
