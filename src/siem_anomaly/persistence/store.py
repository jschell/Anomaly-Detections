from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import polars as pl

from .artifact_types import ArtifactType
from .policy import PersistencePolicy


@dataclass(slots=True)
class EngagementStore:
    root: Path
    policy: PersistencePolicy

    _DIRECTORIES = {
        ArtifactType.AGGREGATE_FEATURE: "features",
        ArtifactType.RELATIONSHIP_STATE: "state",
        ArtifactType.BASELINE: "baselines",
        ArtifactType.MODEL: "models",
        ArtifactType.FINDING: "findings",
        ArtifactType.EVALUATION_RESULT: "evaluation",
        ArtifactType.INCIDENT_EVIDENCE: "incidents",
    }

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "manifests").mkdir(exist_ok=True)
        for directory in self._DIRECTORIES.values():
            (self.root / directory).mkdir(exist_ok=True)

    def write_parquet(
        self,
        artifact_type: ArtifactType,
        relative_path: str,
        frame: pl.DataFrame,
        *,
        explicit_incident_promotion: bool = False,
    ) -> Path:
        self.policy.validate(
            artifact_type,
            explicit_incident_promotion=explicit_incident_promotion,
        )
        target = self.root / self._DIRECTORIES[artifact_type] / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        frame.write_parquet(target)
        return target

    def write_json(
        self,
        artifact_type: ArtifactType,
        relative_path: str,
        payload: dict[str, Any],
        *,
        explicit_incident_promotion: bool = False,
    ) -> Path:
        self.policy.validate(
            artifact_type,
            explicit_incident_promotion=explicit_incident_promotion,
        )
        target = self.root / self._DIRECTORIES[artifact_type] / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return target
