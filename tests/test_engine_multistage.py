from threat_engine.engine import decide

def test_multi_stage_attack_escalates(threat):
    threat["scenarios"].extend([
        {
            "name": "wordpress-probe",
            "category": "web-exploitation",
            "base_score": 0.85,
            "count": 1,
        },
        {
            "name": "generic-backdoor-detection",
            "category": "other",
            "base_score": 0.4,
            "count": 1,
        }
    ])

    result = decide(threat)

    assert result["decision"] == "TEMP_BAN"
    assert "MULTI_STAGE_ATTACK" in result["reason_codes"]
