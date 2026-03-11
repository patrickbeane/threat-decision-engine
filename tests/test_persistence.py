from datetime import datetime, timezone, timedelta
import sqlite3

from threat_engine.persistence import DecisionStore


def _decision(ip: str, decision: str, ttl_seconds: int = 60) -> dict:
    return {
        "ip": ip,
        "decision": decision,
        "ttl_seconds": ttl_seconds,
        "confidence": {"score": 0.9, "label": "high"},
        "reason_codes": ["REPEATED_LOW_CONFIDENCE_ACTIVITY"],
        "scenarios": [],
        "evidence": {"severity": "high", "node_count": 1},
    }


def test_get_active_decision_prefers_highest_rank(tmp_path):
    db_path = tmp_path / "decisions.db"
    store = DecisionStore(db_path=db_path)

    store.store_decision(_decision("1.2.3.4", "WATCH", ttl_seconds=120))
    store.store_decision(_decision("1.2.3.4", "TEMP_BAN", ttl_seconds=120))

    result = store.get_active_decision("1.2.3.4")

    assert result is not None
    assert result["decision"] == "TEMP_BAN"


def test_get_active_decision_skips_expired_rows(tmp_path):
    db_path = tmp_path / "decisions.db"
    store = DecisionStore(db_path=db_path)

    store.store_decision(_decision("5.6.7.8", "PERM_BAN", ttl_seconds=120))
    store.store_decision(_decision("5.6.7.8", "WATCH", ttl_seconds=120))

    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE decisions SET expires_at = ? WHERE ip = ? AND decision = ?",
            (past, "5.6.7.8", "PERM_BAN"),
        )

    result = store.get_active_decision("5.6.7.8")

    assert result is not None
    assert result["decision"] == "WATCH"


def test_get_active_decision_returns_positive_ttl(tmp_path):
    db_path = tmp_path / "decisions.db"
    store = DecisionStore(db_path=db_path)

    store.store_decision(_decision("9.9.9.9", "TEMP_BAN", ttl_seconds=30))

    result = store.get_active_decision("9.9.9.9")

    assert result is not None
    assert 1 <= result["ttl_seconds"] <= 30
