# threat_engine/policies.py

AUTO_BAN_SCENARIOS = {
    "webshell-high-confidence",
    "php-known-backdoor",
}

AUTO_BAN_DECISION = "PERM_BAN"
AUTO_BAN_CONFIDENCE_REQUIRED = 0.7

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

CONFIDENCE_LABEL_ORDER = ["low", "medium", "high"]

CONFIDENCE_LABELS = {
    "low": (0.0, 0.499),
    "medium": (0.5, 0.799),
    "high": (0.8, 1.0),
}

DECISION_TTLS = {
    "TEMP_BAN": 24 * 60 * 60,       # 24 hours
    "PERM_BAN": 14 * 24 * 60 * 60,  # 14 days
    "WATCH": 7 * 24 * 60 * 60       # 7 days
}

DECISION_ORDER = [
    "IGNORE",
    "WATCH",
    "RATE_LIMIT",
    "TEMP_BAN",
    "PERM_BAN",
]

DECISION_RANK = {d: i for i, d in enumerate(DECISION_ORDER)}
