"""Time-series model evaluation gates.

Random Cut Forest is intentionally not a required runtime dependency. It is considered
only after Isolation Forest demonstrates incremental value. This module records that
decision explicitly instead of silently adding another model family.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TimeSeriesModelDecision:
    model: str
    status: str
    reason: str


def random_cut_forest_decision(*, isolation_forest_retained: bool) -> TimeSeriesModelDecision:
    if not isolation_forest_retained:
        return TimeSeriesModelDecision(
            model="random_cut_forest",
            status="deferred",
            reason="Isolation Forest did not establish incremental value; stop model escalation.",
        )
    return TimeSeriesModelDecision(
        model="random_cut_forest",
        status="candidate",
        reason=(
            "Isolation Forest established incremental value; evaluate RCF in a later "
            "time-series-specific benchmark before adding a dependency."
        ),
    )
