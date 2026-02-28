from threat_engine.engine import decide

def test_rule_ignored_if_confidence_too_low(threat):
    threat["confidence"]["score"] = 0.6
    threat["confidence"]["label"] = "medium"

    threat["scenarios"].append({
        "name": "webshell-high-confidence",
        "category": "post-exploitation",
        "base_score": 0.95,
        "count": 1,
    })

    result = decide(threat)

    assert result["decision"] == "TEMP_BAN"

def test_invalid_confidence_label_is_normalized(threat):
    threat["confidence"]["score"] = 0.2
    threat["confidence"]["label"] = "UNTRUSTED_LABEL"

    result = decide(threat)

    assert result["confidence"]["label"] == "low"
