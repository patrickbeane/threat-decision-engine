# threat_engine/explain.py

from threat_engine.utils import format_duration
from threat_engine.validator import validate_and_sort
from threat_engine.engine import decide
from threat_engine.helpers import load_input, ensure_ttl

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
        "Observed on a single node, indicating non-distributed activity at time of detection.",
    "LOW_SCENARIO_VOLUME":
        "Detected activity is a limited amount of firewall scenarios.",
    "PRESERVED_EXISTING_DECISION":
        "An existing enforcement decision was retained because it was equal to or higher than the newly evaluated outcome."
}

def explain_api_input(api_input, as_json=False):
    data = load_input(api_input)
    threats = validate_and_sort(data["threats"])

    for t in threats:
        decision = decide(t, strike_count=1, existing_decision=None)
        ensure_ttl(decision)

        if as_json:
            print(json.dumps(explain_structured(decision), indent=2))
        else:
            print(explain(decision))

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
        "mitre_tactics": decision.get("mitre_tactics", []),
        "mitre_techniques": decision.get("mitre_techniques", []),
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
    mitre_tactics = decision.get("mitre_tactics", [])
    mitre_techniques = decision.get("mitre_techniques", [])

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
                if isinstance(s, dict):
                    lines.append(
                        f"      - {s.get('name')} / {s.get('category')} / "
                        f"base_score: {s.get('base_score')} / count: {s.get('count')} / "
                        f"last_seen: {s.get('last_seen')}"
                    )
                else:
                    lines.append(f"      - {s}")
        if mitre_tactics:
            lines.append(f"MITRE Tactics: {mitre_tactics}")
            if mitre_techniques:
                lines.append(f"MITRE Techniques: ")
                for t in mitre_techniques:
                    lines.append(f"  - {t}")
        if decision["decision"] in ("PERM_BAN", "TEMP_BAN"):
            ttl = decision.get("ttl_seconds")
            lines.append(f"   - TTL remaining: {format_duration(ttl)}")

    return "\n".join(lines)
