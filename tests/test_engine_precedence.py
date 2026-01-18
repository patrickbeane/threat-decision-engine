from threat_engine.engine import decide

def test_temp_ban_wins_over_watch(threat):
    threat["scenarios"].extend([
        {
            "name": "wordpress-probe",
            "category": "web-exploitation",
            "base_score": 0.85,
            "count": 1,
        },
        {
            "name": "webshell-high-confidence",
            "category": "post-exploitation",
            "base_score": 0.95,
            "count": 1,
        }
    ])

    result = decide(threat)

    assert result["decision"] == "PERM_BAN"
