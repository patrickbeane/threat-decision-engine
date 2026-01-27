# threat_engine/explain.py

from threat_engine.utils import format_duration

REASON_EXPLANATIONS = {
    "POST_EXPLOITATION_INDICATORS":
        "High-confidence indicators of post-exploitation activity were detected.",
    "POST_EXPLOITATION_BEHAVIOR":
        "Observed behavior consistent with post-compromise activity, such as backdoors, webshells, or lateral movement.",
    "MULTI_STAGE_ATTACK":
        "Multiple stages of an attack chain were observed within a short time window.",
    "LOW_CONFIDENCE":
        "Signals were observed, but confidence was below the automation threshold.",
    "MULTI_NODE_OBSERVATION":
        "Threat activity was observed independently on multiple nodes.",
    "ESCALATED_MULTI_NODE":
        "Enforcement was escalated due to repeated activity across nodes.",
    "ESCALATED_DISTRIBUTED_ATTACK":
        "Permanent enforcement applied due to coordinated distributed activity.",
    "REPUTATION_ESCALATION_WARNING":
        "Escalated reputation based on attacks within a short window.",
    "REPUTATION_ESCALATION_CRITICAL":
        "Further attacks within a short window, permanent ban applied based on indicators of persistence attacks.",
    "HIGH_SEVERITY_SINGLE_NODE":
        "High severity activity observed on a single node; enforcement applied based on severity.",
    "SINGLE_NODE_ONLY":
        "Observed only on a single node, but severity and confidence justify enforcement across the fleet.",
    "LOW_SCENARIO_VOLUME":
        "Detected activity is a limited amount of firewall scenarios.",
    "PRESERVED_EXISTING_DECISION":
        "An existing enforcement decision was retained because it was equal to or higher than the newly evaluated outcome."
}

def explain_structured(decision: dict) -> dict:
    """Return a structured explanation object."""
    reasons = []
    for reason in decision.get("reason_codes", []):
        reasons.append({
            "code": reason,
            "description": REASON_EXPLANATIONS.get(
                reason,
                f"Unmapped reason code: {reason}"
            )
        })

    return {
        "decision": decision["decision"],
        "ip": decision["ip"],
        "confidence": decision["confidence"],
        "reasons": reasons,
        "evidence": decision.get("evidence"),
    }


def explain(decision: dict) -> str:
    """Return a human-readable explanation string."""
    structured = explain_structured(decision)
    lines = []

    conf = structured["confidence"]
    if isinstance(conf, dict):
        conf = conf.get("label", conf)

    lines.append(
        f"\n"
        f"[{structured['decision']}] {structured['ip']} "
        f"(confidence: {conf})"
    )

    for r in structured["reasons"]:
        lines.append(f"  - {r['description']}")

    ev = structured.get("evidence")
    scenarios = decision.get("scenarios", [])

    if ev or scenarios:
        lines.append("")
        lines.append("Evidence:")
        if ev:
            lines.append(f"  - Nodes observed: {ev.get('node_count')}")
            lines.append(f"  - Severity: {ev.get('severity')}")
            if ev.get("last_seen"):
                lines.append(f"  - Last observed: {ev.get('last_seen')}")
        if scenarios:
            lines.append(f"  - Scenarios ({len(scenarios)}):")
            for s in scenarios:
                lines.append(f"      - {s['name']} / {s['category']} / base_score: {s['base_score']} / count: {s['count']} / last_seen: {s['last_seen']}")
        if decision["decision"] in ("PERM_BAN", "TEMP_BAN"):
            ttl = decision.get("ttl_seconds")
            lines.append(f"   - TTL remaining: {format_duration(ttl)}")

    return "\n".join(lines)
