# threat_engine/config.py

DECISION_TTLS = {
    "TEMP_BAN": 24 * 60 * 60,       # 24 hours
    "PERM_BAN": 14 * 24 * 60 * 60,  # 14 days
    "WATCH": 30 * 24 * 60 * 60      # 30 days
}
