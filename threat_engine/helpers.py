# threat_engine/helpers.py

import json
import pathlib
import urllib.request
from datetime import datetime, timezone, timedelta

from threat_engine.policies import DECISION_TTLS
from threat_engine.errors import ThreatEngineError

def load_input(path_or_url: str) -> dict:
    if path_or_url.startswith(("http://", "https://")):
        with urllib.request.urlopen(path_or_url, timeout=10) as resp:
            return json.load(resp)

    path = pathlib.Path(path_or_url)
    if not path.exists():
        raise ThreatEngineError(f"Input not found: {path}")

    with path.open() as f:
        return json.load(f)

def write_output(decisions: list, output: str | None):
    if not output:
        return

    try:
        with open(output, "w") as f:
            json.dump(decisions, f, indent=2)
    except Exception as e:
        raise ThreatEngineError(f"Failed to write output: {e}")

VALID_CONFIDENCE_LABELS = {"low", "medium", "high"}

def normalize_confidence_label(label: object, score: float) -> str:
    if isinstance(label, str):
        normalized = label.strip().lower()
        if normalized in VALID_CONFIDENCE_LABELS:
            return normalized

    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"

def ensure_ttl(decision: dict):
    ttl = DECISION_TTLS.get(decision["decision"])
    if not ttl:
        decision["expires_at"] = None
        decision.pop("ttl_seconds", None)
        return

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    decision["expires_at"] = expires_at.isoformat()
    decision["ttl_seconds"] = ttl
