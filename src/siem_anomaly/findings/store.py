"""Purpose-specific persistence for anomaly findings."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from siem_anomaly.core.domain import Finding
from siem_anomaly.persistence.policy import ArtifactKind, PersistencePolicy


@dataclass(frozen=True, slots=True)
class FindingStore:
    root: Path
    policy: PersistencePolicy

    def write(
        self,
        findings: tuple[Finding, ...],
        *,
        source: str,
        token: str,
    ) -> Path:
        self.policy.assert_allowed(ArtifactKind.FINDING)
        source_dir = self.root / source.replace(".", "_")
        source_dir.mkdir(parents=True, exist_ok=True)
        destination = source_dir / f"{token}.json"
        payload: list[dict[str, object]] = []
        for finding in findings:
            item = asdict(finding)
            item["start"] = finding.start.isoformat()
            item["end"] = finding.end.isoformat()
            payload.append(item)
        destination.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=_json_default),
            encoding="utf-8",
        )
        return destination


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
