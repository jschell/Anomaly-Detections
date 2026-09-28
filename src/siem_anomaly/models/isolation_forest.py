"""Versioned Isolation Forest over derived aggregate features.

scikit-learn does not currently provide complete type stubs for these APIs, so
unknown-member/type diagnostics are isolated to this integration module.
"""

# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false
# pyright: reportArgumentType=false

import json
import pickle
import shutil
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


@dataclass(frozen=True, slots=True)
class IsolationForestArtifact:
    model_id: str
    feature_version: str
    feature_columns: tuple[str, ...]
    training_start: datetime
    training_end: datetime
    contamination: float
    model_path: Path
    metadata_path: Path


@dataclass(frozen=True, slots=True)
class ModelComparison:
    deterministic_rank: int | None
    model_rank: int | None
    deterministic_precision_at_n: float
    model_precision_at_n: float
    retained: bool
    reason: str


def _feature_columns(frame: pl.DataFrame) -> tuple[str, ...]:
    excluded = {"actor", "window"}
    return tuple(
        name for name, dtype in frame.schema.items() if name not in excluded and dtype.is_numeric()
    )


def _matrix(frame: pl.DataFrame, columns: tuple[str, ...]) -> np.ndarray:
    if not columns:
        raise ValueError("No numeric aggregate feature columns are available")
    return frame.select(
        [pl.col(column).cast(pl.Float64).fill_null(0.0) for column in columns]
    ).to_numpy()


def fit_isolation_forest(
    actor_hour: pl.DataFrame,
    *,
    models_root: Path,
    model_id: str,
    feature_version: str,
    contamination: float = 0.02,
    random_state: int = 42,
) -> IsolationForestArtifact:
    """Fit an engagement-local candidate from derived actor-hour features."""
    if actor_hour.is_empty():
        raise ValueError("Cannot train Isolation Forest on an empty feature set")
    columns = _feature_columns(actor_hour)
    matrix = _matrix(actor_hour, columns)
    pipeline = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "isolation_forest",
                IsolationForest(
                    contamination=contamination,
                    random_state=random_state,
                    n_estimators=200,
                ),
            ),
        ]
    )
    pipeline.fit(matrix)
    training_start = _as_utc(actor_hour.get_column("window").min())
    training_end = _as_utc(actor_hour.get_column("window").max())

    model_dir = models_root / "_candidates" / "isolation_forest" / model_id
    if model_dir.exists():
        shutil.rmtree(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "model.pkl"
    metadata_path = model_dir / "metadata.json"
    with model_path.open("wb") as handle:
        pickle.dump(pipeline, handle)

    artifact = IsolationForestArtifact(
        model_id=model_id,
        feature_version=feature_version,
        feature_columns=columns,
        training_start=training_start,
        training_end=training_end,
        contamination=contamination,
        model_path=model_path,
        metadata_path=metadata_path,
    )
    _write_metadata(artifact, status="candidate")
    return artifact


def finalize_isolation_forest(
    artifact: IsolationForestArtifact,
    comparison: ModelComparison,
    *,
    models_root: Path,
) -> IsolationForestArtifact | None:
    """Retain an approved candidate or remove it when it adds no operational value."""
    candidate_dir = artifact.model_path.parent
    if not comparison.retained:
        if candidate_dir.exists():
            shutil.rmtree(candidate_dir)
        return None

    retained_dir = models_root / "isolation_forest" / artifact.model_id
    if retained_dir.exists():
        shutil.rmtree(retained_dir)
    retained_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(candidate_dir), str(retained_dir))
    retained = replace(
        artifact,
        model_path=retained_dir / "model.pkl",
        metadata_path=retained_dir / "metadata.json",
    )
    _write_metadata(retained, status="retained", comparison=comparison)
    return retained


def score_isolation_forest(
    actor_hour: pl.DataFrame,
    artifact: IsolationForestArtifact,
) -> pl.DataFrame:
    """Return raw model components and anomaly ranking score."""
    with artifact.model_path.open("rb") as handle:
        pipeline = cast(Pipeline, pickle.load(handle))
    matrix = _matrix(actor_hour, artifact.feature_columns)
    estimator = cast(IsolationForest, pipeline.named_steps["isolation_forest"])
    scaled = pipeline.named_steps["scale"].transform(matrix)
    raw_score = estimator.score_samples(scaled)
    decision = estimator.decision_function(scaled)
    labels = estimator.predict(scaled)
    return actor_hour.select(["actor", "window"]).with_columns(
        [
            pl.Series("iforest_score_samples", raw_score),
            pl.Series("iforest_decision_function", decision),
            pl.Series("anomaly_score", -raw_score),
            pl.Series("model_flag", labels == -1),
        ]
    )


def compare_model_to_deterministic(
    scores: pl.DataFrame,
    *,
    incident_entities: tuple[str, ...],
    incident_start: datetime,
    incident_end: datetime,
    deterministic_rank: int | None,
    deterministic_precision_at_n: float,
    n: int = 10,
) -> ModelComparison:
    """Approve retention only when incident ranking or precision improves."""
    ranked = scores.sort("anomaly_score", descending=True)
    labels = [
        (
            str(row["actor"]) in incident_entities
            and _as_utc(row["window"]) >= incident_start.astimezone(UTC)
            and _as_utc(row["window"]) <= incident_end.astimezone(UTC)
        )
        for row in ranked.iter_rows(named=True)
    ]
    model_rank = next((index for index, value in enumerate(labels, start=1) if value), None)
    top = labels[:n]
    model_precision = sum(top) / len(top) if top else 0.0

    rank_improved = model_rank is not None and (
        deterministic_rank is None or model_rank < deterministic_rank
    )
    precision_improved = model_precision > deterministic_precision_at_n
    retained = rank_improved or precision_improved
    if rank_improved:
        reason = "incident rank improved"
    elif precision_improved:
        reason = f"precision@{n} improved"
    else:
        reason = "no incremental operational improvement"
    return ModelComparison(
        deterministic_rank=deterministic_rank,
        model_rank=model_rank,
        deterministic_precision_at_n=deterministic_precision_at_n,
        model_precision_at_n=model_precision,
        retained=retained,
        reason=reason,
    )


def _write_metadata(
    artifact: IsolationForestArtifact,
    *,
    status: str,
    comparison: ModelComparison | None = None,
) -> None:
    payload = asdict(artifact)
    payload["training_start"] = artifact.training_start.isoformat()
    payload["training_end"] = artifact.training_end.isoformat()
    payload["model_path"] = str(artifact.model_path)
    payload["metadata_path"] = str(artifact.metadata_path)
    payload["status"] = status
    if comparison is not None:
        payload["comparison"] = asdict(comparison)
    artifact.metadata_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _as_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
