from threat_engine.validator import validate_and_sort

def _threat(ip: str) -> dict:
    return {
        "ip": ip,
        "last_seen": "2026-02-11T00:00:00Z",
        "confidence": {"score": 0.9, "label": "high"},
        "severity": {"score": 8.0, "level": "high"},
        "scenarios": [
            {
                "name": "suspicious-probe",
                "category": "reconnaissance",
                "base_score": 0.6,
            }
        ],
        "source": ["triton"],
    }

def test_validator_accepts_valid_ipv4():
    threats = validate_and_sort([_threat("1.2.3.4")])
    assert len(threats) == 1
    assert threats[0]["ip"] == "1.2.3.4"

def test_validator_strips_whitespace_from_ipv4():
    threats = validate_and_sort([_threat("  1.2.3.4  ")])
    assert len(threats) == 1
    assert threats[0]["ip"] == "1.2.3.4"

def test_validator_normalizes_valid_ipv6():
    threats = validate_and_sort([_threat("2001:0DB8:0000:0000:0000:ff00:0042:8329")])
    assert len(threats) == 1
    assert threats[0]["ip"] == "2001:db8::ff00:42:8329"

def test_validator_strips_whitespace_from_ipv6():
    threats = validate_and_sort([
        _threat("  2001:0DB8:0000:0000:0000:ff00:0042:8329  ")
    ])
    assert len(threats) == 1
    assert threats[0]["ip"] == "2001:db8::ff00:42:8329"

def test_validator_drops_invalid_ips():
    raw = [
        _threat("not-an-ip"),
        _threat("999.999.999.999"),
        _threat(""),
        _threat("  "),
    ]
    threats = validate_and_sort(raw)
    assert threats == []

def test_validator_normalizes_invalid_confidence_label():
    t = _threat("1.2.3.4")
    t["confidence"]["label"] = "unexpected"
    t["confidence"]["score"] = 0.9

    threats = validate_and_sort([t])

    assert len(threats) == 1
    assert threats[0]["confidence"]["label"] == "high"
