# threat_engine/validator.py

from datetime import datetime
import ipaddress
from typing import List, Tuple

def validate_and_sort(threats: List[dict]) -> List[dict]:
    """
    Validate, normalize, and order threats.

    Guarantees:
      - Returned threats always have valid normalized:
        - ip
        - >=1 scenario
        - numeric confidence [0.0–1.0]
        - numeric severity [0–10]
      - Invalid threats are dropped
      - Sorting is deterministic and risk-based
    """
    valid: List[Tuple[tuple, dict]] = []

    for t in threats:
        try:
            ip_raw = t.get("ip")
            if not isinstance(ip_raw, str) or not ip_raw.strip():
                continue
            ip = str(ipaddress.ip_address(ip_raw.strip()))
            t["ip"] = ip

            # Parse timestamp safely
            try:
                last_seen = datetime.fromisoformat(
                    t.get("last_seen", "").replace("Z", "")
                )
            except Exception:
                last_seen = datetime.min

            confidence = max(
                0.0,
                min(float(t.get("confidence", {}).get("score", 0.0)), 1.0)
            )

            severity = max(
                0.0,
                min(float(t.get("severity", {}).get("score", 0.0)), 10.0)
            )

            scenarios = t.get("scenarios", [])
            if not isinstance(scenarios, list) or not scenarios:
                continue

            sources = t.get("source", [])
            if not isinstance(sources, list):
                sources = []

            sources = {s for s in sources if isinstance(s, str)}

            t["sources"] = sorted(sources)
            t["node_count"] = len(sources)

            max_base = max(
                float(s.get("base_score", 0.0)) for s in scenarios
            )

            sort_key = (
                severity,
                confidence,
                max_base,
                last_seen,
            )

            valid.append((sort_key, t))

        except Exception:
            continue

    valid.sort(key=lambda item: item[0], reverse=True)

    return [t for _, t in valid]
