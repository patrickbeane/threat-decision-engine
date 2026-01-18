from threat_engine.explain import explain

def test_explain_contains_reasons(sample_decision):
    text = explain(sample_decision)
    assert "post-exploitation" in text.lower()

def test_explain_handles_unknown_reason(sample_decision):
    sample_decision["reason_codes"].append("UNKNOWN_REASON")
    text = explain(sample_decision)
    assert "unmapped reason code" in text.lower()

def test_explain_never_raises(sample_decision):
    sample_decision["reason_codes"].append(None)
    text = explain(sample_decision)
    assert isinstance(text, str)
