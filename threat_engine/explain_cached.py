# threat_engine/explain_cached.py

from threat_engine.reasons import reason_description
from threat_engine.utils import format_duration

def explain_cached(decision: dict) -> str:
    lines = []

    ttl = decision.get("ttl_seconds")
    lines.append(f"[{decision['decision']}] {decision['ip']} (confidence: {decision['confidence']['label']}) - TTL remaining: {format_duration(ttl)}")

    mitre_tactics = decision.get("mitre_tactics", [])
    mitre_techniques = decision.get("mitre_techniques", [])

    for reason in decision.get("reason_codes", []):
        lines.append(f"  - {reason_description(reason)}")

    ev = decision.get("evidence", {})
    if ev:
        lines.append("\nEvidence (cached decision):")
        lines.append(f"  - Nodes observed: {ev.get('node_count')}")
        lines.append(f"  - Severity: {ev.get('severity')}")
        if mitre_tactics:
            lines.append(f"\nMITRE Tactics: {mitre_tactics}")
            if mitre_techniques:
                lines.append(f"MITRE Techniques: ")
                for t in mitre_techniques:
                    lines.append(f"  - {t}")
        if ev.get("last_seen"):
            lines.append(f"  - Last observed: {ev.get('last_seen')}")

    scenarios = decision.get("scenarios", [])
    if scenarios:
        lines.append("\nScenarios observed:")
        for s in scenarios:
            if isinstance(s, dict):
                lines.append(f"  - {s.get('name')} (category: {s.get('category')}, base_score: {s.get('base_score')})")
            else:
                lines.append(f"  - {s}")


    return "\n".join(lines)


def explain_cached_structured(decision: dict) -> dict:
    return {
        "ip": decision["ip"],
        "decision": decision["decision"],
        "confidence": decision["confidence"],
        "severity": decision["evidence"]["severity"],
        "strike_count": decision.get("strike_count", 0),
        "node_count": decision["evidence"]["node_count"],
        "reason_codes": decision["reason_codes"],
        "scenarios": decision.get("scenarios", []),
        "mitre_tactics": decision.get("mitre_tactics", []),
        "mitre_techniques": decision.get("mitre_techniques", []),
        "ttl_seconds": decision.get("ttl_seconds"),
        "first_seen": decision.get("first_seen"),
        "last_seen": decision.get("last_seen"),
        "source": "cache",
    }
