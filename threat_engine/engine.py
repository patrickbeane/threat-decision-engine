# threat_engine/engine.py

from threat_engine.config import DECISION_TTLS
from threat_engine.policies import DECISION_RANK
from threat_engine.rules import RULES
from threat_engine.reasons import Reason


def decide(threat: dict) -> dict:
    """
    Return a decision object:
    {
      ip,
      decision,
      ttl_seconds,
      confidence,
      reason_codes,
      evidence
    }
    """
    confidence = threat["confidence"]["score"]
    confidence_label = threat["confidence"]["label"]
    severity = threat["severity"]["level"]
    node_count = threat.get("node_count", 1)
    last_seen = threat.get("last_seen", "")
    proposals: list[dict] = []
    reasons: list[str] = []

    for rule in RULES:
        result = rule(threat)
        if not result:
            continue
        if confidence < result["confidence_required"]:
            continue
        proposals.append(result)

    final_decision = "WATCH"

    if node_count >= 2:
        confidence += 0.15
        reasons.append(Reason.MULTI_NODE_OBSERVATION)

    if node_count >= 3:
        confidence += 0.25
        reasons.append(Reason.ESCALATED_DISTRIBUTED_ATTACK)

    confidence = min(confidence, 1.0)

    if confidence >= 0.7 and severity == "critical" and node_count == 1:
        final_decision = "TEMP_BAN"
        reasons.append(Reason.HIGH_SEVERITY_SINGLE_NODE)

    for p in proposals:
        if DECISION_RANK[p["decision"]] > DECISION_RANK[final_decision]:
            final_decision = p["decision"]
        reasons.append(p["reason"])

    if final_decision == "WATCH" and node_count >= 2:
        final_decision = "TEMP_BAN"
        reasons.append(Reason.ESCALATED_MULTI_NODE)

    elif final_decision == "TEMP_BAN" and node_count >= 3:
        final_decision = "PERM_BAN"
        reasons.append(Reason.ESCALATED_DISTRIBUTED_ATTACK)

    if final_decision == "WATCH":
        if node_count == 1:
            reasons.append(Reason.SINGLE_NODE_ONLY)

        if len(threat["scenarios"]) == 1:
            reasons.append(Reason.LOW_SCENARIO_VOLUME)

        if not reasons:
            reasons.append(Reason.INSUFFICIENT_EVIDENCE)


    ttl = DECISION_TTLS.get(final_decision)

    valid_reasons = {
        value for value in vars(Reason).values()
        if isinstance(value, str)
    }

    unknown = set(reasons) - valid_reasons
    if unknown:
        raise ValueError(
            f"Unknown reason codes generated: {unknown}"
        )

    return {
        "ip": threat["ip"],
        "decision": final_decision,
        "ttl_seconds": ttl,
        "confidence": {
            "score": round(confidence, 2),
            "label": confidence_label,
        },
        "reason_codes": sorted(set(reasons)),
        "evidence": {
            "scenario_count": len(threat["scenarios"]),
            "node_count": node_count,
            "categories": sorted(
                {s.get("category", "unknown") for s in threat["scenarios"]}
            ),
            "severity": severity,
        },
    }
