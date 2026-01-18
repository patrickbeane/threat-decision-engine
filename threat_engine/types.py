# threat_engine/types.py

from typing import TypedDict, List, Literal, Optional, Callable
from datetime import datetime

class Scenario(TypedDict):
    name: str
    category: str
    base_score: float
    count: int
    last_seen: str


class Confidence(TypedDict):
    score: float
    label: Literal["low", "medium", "high"]


class Severity(TypedDict):
    level: Literal["low", "medium", "high", "critical"]
    score: int


class Threat(TypedDict):
    ip: str
    scenarios: List[Scenario]
    confidence: Confidence
    severity: Severity
    source: List[str]

Decision = Literal[
    "IGNORE",
    "WATCH",
    "RATE_LIMIT",
    "TEMP_BAN",
    "PERM_BAN",
]


class RuleResult(TypedDict):
    decision: Decision
    confidence_required: float
    reason: str


class Evidence(TypedDict):
    scenario_count: int
    node_count: int
    categories: List[str]
    severity: str


class DecisionOutput(TypedDict):
    ip: str
    decision: Decision
    ttl_seconds: Optional[int]
    confidence: Confidence
    reason_codes: List[str]
    evidence: Evidence


class NormalizedThreat(TypedDict):
    threat: Threat
    last_seen: datetime
    confidence: float
    severity: float


Rule = Callable[[Threat], Optional[RuleResult]]
