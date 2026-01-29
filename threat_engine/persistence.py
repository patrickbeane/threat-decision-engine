# threat_engine/persistence.py

import sqlite3
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
DEFAULT_DB = PROJECT_ROOT / Path("decisions.db")

class DecisionStore:
    def __init__(self, db_path: Path = DEFAULT_DB):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):

        with self._connect() as conn:

            conn.executescript("""
                CREATE TABLE IF NOT EXISTS decisions (
                    ip TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    confidence_label TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    node_count INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    mitre_tactics TEXT,
                    mitre_techniques TEXT,
                    expires_at TEXT,
                    reason_codes TEXT NOT NULL,
                    scenarios TEXT,
                    PRIMARY KEY (ip, decision)
                );
                CREATE TABLE IF NOT EXISTS reputation (
                    ip TEXT PRIMARY KEY,
                    strike_count INTEGER NOT NULL DEFAULT 0,
                    last_seen TEXT NOT NULL
                    );
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                            value TEXT
		        );
            """)

    def get_strikes(self, ip: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT strike_count FROM reputation WHERE ip = ?",
                (ip,)
            ).fetchone()
            return row["strike_count"] if row else 0

    def record_strike(self, ip: str, increment: bool = True) -> int:
        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            row = conn.execute(
                "SELECT strike_count, last_seen FROM reputation WHERE ip = ?",
                (ip,)
            ).fetchone()

            if not row:
                conn.execute(
                    "INSERT INTO reputation (ip, strike_count, last_seen) VALUES (?, ?, ?)",
                    (ip, 1 if increment else 0, now)
                )
                return 1 if increment else 0

            strike_count = row["strike_count"]
            last_seen = datetime.fromisoformat(row["last_seen"])

            # increment only if outside cooldown window
            if increment and (datetime.now(timezone.utc) - last_seen).total_seconds() >= 300:
                strike_count += 1

            conn.execute(
                "UPDATE reputation SET strike_count = ?, last_seen = ? WHERE ip = ?",
                (strike_count, now, ip)
            )

            return strike_count

    def get_active_decision(self, ip: str) -> dict | None:
        now = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            row = conn.execute("""
                SELECT *
                FROM decisions
                WHERE ip = ?
                  AND (expires_at IS NULL OR expires_at > ?)
            """, (ip, now)).fetchone()

        if not row:
            return None

        ttl_seconds = None
        if row["expires_at"]:
            ttl_seconds = int(
                (datetime.fromisoformat(row["expires_at"]) - datetime.now(timezone.utc))
                .total_seconds()
            )

        return {
            "ip": row["ip"],
            "decision": row["decision"],
            "ttl_seconds": ttl_seconds,
            "confidence": {
                "score": row["confidence_score"],
                "label": row["confidence_label"],
            },
            "reason_codes": json.loads(row["reason_codes"]),
            "evidence": {
                "node_count": row["node_count"],
                "severity": row["severity"],
            },
            "scenarios": json.loads(row["scenarios"]) if row["scenarios"] else [],
            "mitre_tactics": json.loads(row["mitre_tactics"]) if row["mitre_tactics"] else [],
            "mitre_techniques": json.loads(row["mitre_techniques"]) if row["mitre_techniques"] else [],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "source": "sqlite",
        }

    def get_active_decisions(self, limit: int | None = None) -> list[dict]:
        now = datetime.now(timezone.utc).isoformat()

        query = """
            SELECT *
            FROM decisions
            WHERE expires_at IS NULL OR expires_at > ?
            ORDER BY last_seen DESC
        """

        if limit:
            query += f" LIMIT {limit}"

        with self._connect() as conn:
            rows = conn.execute(query, (now,)).fetchall()

        results = []
        for row in rows:
            ttl_seconds = None
            if row["expires_at"]:
                ttl_seconds = int(
                    (datetime.fromisoformat(row["expires_at"]) - datetime.now(timezone.utc))
                    .total_seconds()
                )

            results.append({
                "ip": row["ip"],
                "decision": row["decision"],
                "ttl_seconds": ttl_seconds,
                "confidence": {
                    "score": row["confidence_score"],
                    "label": row["confidence_label"],
                },
                "reason_codes": json.loads(row["reason_codes"]),
                "evidence": {
                    "node_count": row["node_count"],
                    "severity": row["severity"],
                },
                "scenarios": json.loads(row["scenarios"]) if row["scenarios"] else [],
                "mitre_tactics": json.loads(row["mitre_tactics"]) if row["mitre_tactics"] else [],
                "mitre_techniques": json.loads(row["mitre_techniques"]) if row["mitre_techniques"] else [],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "source": "sqlite",
            })

        return results


    def store_decision(self, decision: dict):
        now = datetime.now(timezone.utc).isoformat()
        ttl = decision.get("ttl_seconds")

        expires_at = (
            (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
            if ttl else None
        )

        severity_data = decision["evidence"].get("severity", {})  # safe get

        mitre_tactics = json.dumps(severity_data.get("mitre_tactics", [])) or None
        mitre_techniques = json.dumps(severity_data.get("mitre_techniques", [])) or None
    
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO decisions (
                    ip, decision,
                    confidence_score, confidence_label,
                    severity, node_count,
                    first_seen, last_seen,
                    mitre_tactics, mitre_techniques,
                    expires_at, reason_codes,
                    scenarios
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, decision) DO UPDATE SET
                    confidence_score = excluded.confidence_score,
                    confidence_label = excluded.confidence_label,
                    severity = excluded.severity,
                    node_count = excluded.node_count,
                    last_seen = excluded.last_seen,
                    mitre_tactics = excluded.mitre_tactics,
                    mitre_techniques = excluded.mitre_techniques,
                    expires_at = excluded.expires_at,
                    reason_codes = excluded.reason_codes,
                    scenarios = excluded.scenarios
            """, (
                decision["ip"],
                decision["decision"],
                decision["confidence"]["score"],
                decision["confidence"]["label"],
                decision["evidence"]["severity"],
                decision["evidence"]["node_count"],
                now,   # first_seen (only used on insert)
                now,   # last_seen (always updated)
                expires_at,
                mitre_tactics or None,
                mitre_techniques or None,
                json.dumps(decision["reason_codes"]),
                json.dumps(decision.get("scenarios", [])),
            ))

    def remove_lower_decisions(self, ip: str, new_decision: str) -> int:
        from threat_engine.policies import DECISION_RANK

        new_rank = DECISION_RANK[new_decision]

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT decision FROM decisions WHERE ip = ?",
                (ip,)
            ).fetchall()

            deleted = 0
            for row in rows:
                existing_decision = row["decision"]
                if DECISION_RANK.get(existing_decision, -1) < new_rank:
                    conn.execute(
                        "DELETE FROM decisions WHERE ip = ? AND decision = ?",
                        (ip, existing_decision),
                    )
                    deleted += 1

            return deleted


    def set_metadata(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def get_metadata(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = ?",
                (key,),
            ).fetchone()
            return row[0] if row else None
