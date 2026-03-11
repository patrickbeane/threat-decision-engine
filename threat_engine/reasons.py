# threat_engine/reasons.py

class Reason:
    POST_EXPLOITATION_INDICATORS = "POST_EXPLOITATION_INDICATORS"
    POST_EXPLOITATION_BEHAVIOR = "POST_EXPLOITATION_BEHAVIOR"
    MULTI_STAGE_ATTACK = "MULTI_STAGE_ATTACK"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    MULTI_NODE_OBSERVATION = "MULTI_NODE_OBSERVATION"
    ESCALATED_MULTI_NODE = "ESCALATED_MULTI_NODE"
    ESCALATED_DISTRIBUTED_ATTACK = "ESCALATED_DISTRIBUTED_ATTACK"

    INSUFFICIENT_CONFIDENCE = "INSUFFICIENT_CONFIDENCE"
    SINGLE_NODE_ONLY = "SINGLE_NODE_ONLY"
    LOW_SCENARIO_VOLUME = "LOW_SCENARIO_VOLUME"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

    REPUTATION_ESCALATION_WARNING = "REPUTATION_ESCALATION_WARNING"
    REPUTATION_ESCALATION_CRITICAL = "REPUTATION_ESCALATION_CRITICAL"

    HIGH_SEVERITY_SINGLE_NODE = "HIGH_SEVERITY_SINGLE_NODE"
    HIGH_SEVERITY_EXPLOIT = "HIGH_SEVERITY_EXPLOIT"
    REPEATED_LOW_CONFIDENCE_ACTIVITY = "REPEATED_LOW_CONFIDENCE_ACTIVITY"

    PRESERVED_EXISTING_DECISION = "PRESERVED_EXISTING_DECISION"


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
    Reason.INSUFFICIENT_EVIDENCE:
        "Not enough evidence was present to justify enforcement.",
    Reason.LOW_SCENARIO_VOLUME:
        "Detected activity is a limited amount of firewall scenarios.",
}


def reason_description(code: object) -> str:
    if isinstance(code, str):
        return REASON_EXPLANATIONS.get(code, f"Unmapped reason code: {code}")
    return "Unmapped reason code: unknown"
