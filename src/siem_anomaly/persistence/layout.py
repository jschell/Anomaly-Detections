"""Filesystem layout for a single engagement."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class EngagementPaths:
    root: Path

    @property
    def manifests(self) -> Path:
        return self.root / "manifests"

    @property
    def features(self) -> Path:
        return self.root / "features"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def baselines(self) -> Path:
        return self.root / "baselines"

    @property
    def models(self) -> Path:
        return self.root / "models"

    @property
    def findings(self) -> Path:
        return self.root / "findings"

    @property
    def evaluation(self) -> Path:
        return self.root / "evaluation"

    @property
    def investigations(self) -> Path:
        return self.root / "investigations"

    @property
    def incidents(self) -> Path:
        return self.root / "incidents"

    def initialize(self) -> None:
        for path in (
            self.manifests,
            self.features,
            self.state,
            self.baselines,
            self.models,
            self.findings,
            self.evaluation,
            self.investigations,
            self.incidents,
        ):
            path.mkdir(parents=True, exist_ok=True)
