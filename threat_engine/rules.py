# threat_engine/rules.py

from threat_engine.policies import (
    AUTO_BAN_SCENARIOS,
    AUTO_BAN_DECISION,
)

def rule_known_backdoor(threat):
    for s in threat["scenarios"]:
        if s["name"] in AUTO_BAN_SCENARIOS:
            return {
                "decision": AUTO_BAN_DECISION,
                "confidence_required": 0.7,
                "reason": "POST_EXPLOITATION_INDICATORS",
            }

def rule_multi_stage_attack(threat):
    categories = {s["category"] for s in threat["scenarios"]}
    if len(threat["scenarios"]) >= 3 and len(categories) >= 2:
        return {
            "decision": "TEMP_BAN",
            "confidence_required": 0.6,
            "reason": "MULTI_STAGE_ATTACK",
        }

def rule_high_severity_exploit(threat):
    for s in threat["scenarios"]:
        if (
            s.get("category") == "exploit"
            and s.get("base_score", 0) >= 0.8
        ):
            return {
                "decision": "TEMP_BAN",
                "confidence_required": 0.65,
                "reason": "HIGH_SEVERITY_EXPLOIT",
            }

def rule_repeated_noise(threat):
    if (
        len(threat["scenarios"]) >= 5
        and max(s.get("base_score", 0) for s in threat["scenarios"]) < 0.4
    ):
        return {
            "decision": "TEMP_BAN",
            "confidence_required": 0.4,
            "reason": "REPEATED_LOW_CONFIDENCE_ACTIVITY",
        }

def rule_post_exploitation_behavior(threat):
    for s in threat["scenarios"]:
        if s.get("category") == "post-exploitation":
            return {
                "decision": "TEMP_BAN",
                "confidence_required": 0.6,
                "reason": "POST_EXPLOITATION_BEHAVIOR",
            }

RULES = [
    rule_known_backdoor,
    rule_post_exploitation_behavior,
    rule_multi_stage_attack,
    rule_high_severity_exploit,
    rule_repeated_noise,
]
