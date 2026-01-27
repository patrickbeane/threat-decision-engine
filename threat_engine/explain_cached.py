# threat_engine/explain_cached.py

from threat_engine.reasons import Reason
from threat_engine.utils import format_duration

REASON_EXPLANATIONS = {
    Reason.POST_EXPLOITATION_INDICATORS:
        "High-confidence indicators of post-exploitation activity were detected.",
    Reason.POST_EXPLOITATION_BEHAVIOR:
        "Observed behavior consistent with post-compromise activity, such as backdoors, webshells, or lateral movement.",
    Reason.MULTI_STAGE_ATTACK:
        "Multiple stages of an attack chain were observed within a short time window.",
    Reason.LOW_CONFIDENCE:
        "Signals were observed, but confidence was below the automation threshold.",
    Reason.SINGLE_NODE_ONLY:
        "Threat activity was observed from a single node only.",
    Reason.HIGH_SEVERITY_SINGLE_NODE:
        "High severity exploit activity was observed, but only from a single node.",
    Reason.MULTI_NODE_OBSERVATION:
        "Threat activity was observed independently on multiple nodes.",
    Reason.ESCALATED_MULTI_NODE:
        "Enforcement was escalated due to repeated activity across nodes.",
    Reason.ESCALATED_DISTRIBUTED_ATTACK:
        "Permanent enforcement applied due to coordinated distributed activity.",
    Reason.HIGH_SEVERITY_EXPLOIT:
        "High severity exploit activity detected.",
    Reason.REPEATED_LOW_CONFIDENCE_ACTIVITY:
        "Repeated low-confidence activity observed.",
    Reason.REPUTATION_ESCALATION_WARNING:
        "Escalated reputation based on attacks within a short window.",
    Reason.REPUTATION_ESCALATION_CRITICAL:
        "Further attacks within a short window, permanent ban applied based on indicators of persistence attacks.",
    Reason.PRESERVED_EXISTING_DECISION:
        "An existing enforcement decision was retained because it was equal to or higher than the newly evaluated outcome.",
}

def explain_cached(decision: dict) -> str:
    lines = []

    lines.append(f"[{decision['decision']}] {decision['ip']} (confidence: {decision['confidence']['label']})")

    for reason in decision.get("reason_codes", []):
        lines.append(f"  - {REASON_EXPLANATIONS.get(reason, reason)}")

    ev = decision.get("evidence", {})
    if ev:
        lines.append("\nEvidence (cached decision):")
        lines.append(f"  - Nodes observed: {ev.get('node_count')}")
        lines.append(f"  - Severity: {ev.get('severity')}")
        if ev.get("last_seen"):
            lines.append(f"  - Last observed: {ev.get('last_seen')}")

        if decision["decision"] in ("PERM_BAN", "TEMP_BAN"):
            ttl = decision.get("ttl_seconds")
            lines.append(f"  - TTL remaining: {format_duration(ttl)}")

    scenarios = decision.get("scenarios", [])
    if scenarios:
        lines.append("\nScenarios observed:")
        for s in scenarios:
            lines.append(f"  - {s.get('name')} (category: {s.get('category')}, base_score: {s.get('base_score')})")

    return "\n".join(lines)


def explain_cached_structured(decision: dict) -> dict:
    return {
        "ip": decision["ip"],
        "decision": decision["decision"],
        "confidence": decision["confidence"],
        "severity": decision["evidence"]["severity"],
        "strike_count": decision["strike_count"],
        "node_count": decision["evidence"]["node_count"],
        "reason_codes": decision["reason_codes"],
        "scenarios": decision.get("scenarios", []),
        "ttl_seconds": decision.get("ttl_seconds"),
        "first_seen": decision.get("first_seen"),
        "last_seen": decision.get("last_seen"),
        "source": "cache",
    }
