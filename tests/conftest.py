import copy
import pytest
from threat_engine.explain import explain

BASE_THREAT = {
    "ip": "1.2.3.4",
    "confidence": {"score": 0.9, "label": "high"},
    "severity": {"level": "critical", "score": 9},
    "scenarios": [
        {
            "name": "suspicious-probe",
            "category": "reconnaissance",
            "base_score": 0.6,
            "count": 1,
        }
    ],
}

@pytest.fixture
def threat():
    return copy.deepcopy(BASE_THREAT)

@pytest.fixture
def sample_decision():
    return {
        "ip": "1.2.3.4",
        "decision": "BLOCK",
        "confidence": 0.92,
        "reason_codes": [
            "POST_EXPLOITATION_INDICATORS",
            "MULTI_STAGE_ATTACK",
        ],
        "evidence": {
            "scenario_count": 3,
            "categories": ["reconnaissance", "exploit", "post-exploitation"],
            "severity": "critical",
        },
    }

def test_explain_contains_header(sample_decision):
    text = explain(sample_decision)

    assert "BLOCK" in text
    assert "1.2.3.4" in text
    assert "0.92" in text

def test_explain_expands_reason_codes(sample_decision):
    text = explain(sample_decision).lower()

    assert "post-exploitation" in text
    assert "multiple stages" in text

def test_explain_includes_evidence_section(sample_decision):
    text = explain(sample_decision)

    assert "Evidence:" in text
    assert "Scenarios observed" in text
    assert "reconnaissance" in text

def test_explain_without_evidence():
    decision = {
        "ip": "5.6.7.8",
        "decision": "ALLOW",
        "confidence": 0.2,
        "reason_codes": ["LOW_CONFIDENCE"],
    }

    text = explain(decision)

    assert "Evidence:" not in text

def test_explain_handles_unknown_reason(sample_decision):
    sample_decision["reason_codes"].append("ALIENS")

    text = explain(sample_decision).lower()

    assert "unmapped reason code" in text

def test_explain_preserves_reason_order(sample_decision):
    text = explain(sample_decision)

    first = text.find("post-exploitation")
    second = text.find("multiple stages")

    assert first < second
