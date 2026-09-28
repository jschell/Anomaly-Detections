from enum import StrEnum


class ArtifactType(StrEnum):
    AGGREGATE_FEATURE = "aggregate_feature"
    RELATIONSHIP_STATE = "relationship_state"
    BASELINE = "baseline"
    MODEL = "model"
    FINDING = "finding"
    EVALUATION_RESULT = "evaluation_result"
    INCIDENT_EVIDENCE = "incident_evidence"
