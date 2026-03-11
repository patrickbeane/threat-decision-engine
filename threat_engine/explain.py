# threat_engine/explain.py

import json

from threat_engine.utils import format_duration
from threat_engine.validator import validate_and_sort
from threat_engine.engine import decide
from threat_engine.helpers import load_input, ensure_ttl
from threat_engine.reasons import reason_description

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
            "description": reason_description(reason),
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
