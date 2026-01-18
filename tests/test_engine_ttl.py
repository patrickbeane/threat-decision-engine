from threat_engine.engine import decide

def test_ttl_derived_from_severity(threat):
    threat["severity"]["level"] = "critical"

    threat["scenarios"].append({
        "name": "webshell-high-confidence",
        "category": "post-exploitation",
        "base_score": 0.95,
        "count": 1,
    })

    result = decide(threat)

    assert result["ttl_seconds"] == 86400
