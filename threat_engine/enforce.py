# threat_engine/enforce.py

import subprocess
from threat_engine.config import DECISION_TTLS
from threat_engine.utils import format_duration

WRAPPER = "/usr/bin/crowdsec-enforce"

def format_enforcement_preview(decisions):
    lines = ["\nEnforcement preview (no changes applied):\n"]
    for d in decisions:
        if d["decision"] not in ("PERM_BAN", "TEMP_BAN"):
            continue

        ttl = format_duration(d.get("ttl_seconds"))

        reasons = ",".join(d.get("reason_codes", [])) or "n/a"

        lines.append(
            f" - {d['decision']} {d['ip']} "
            f"(ttl={ttl}, severity={d.get('evidence', {}).get('severity')}, reasons={reasons})"
        )

    lines.append("\nRe-run with --yes to apply these actions.")
    return "\n".join(lines)

def enforce_crowdsec(decision: dict):
    action = decision.get("decision")
    ip = decision.get("ip")

    if action not in ("PERM_BAN", "TEMP_BAN"):
        return

    # Resolve TTL
    ttl_seconds = decision.get("ttl_seconds") or DECISION_TTLS.get(action)

    if not ttl_seconds:
        raise ValueError("TEMP_BAN requires ttl_seconds")

    duration = format_duration(ttl_seconds)

    reason_codes = decision.get("reason_codes", [])
    reason = ",".join(sorted(set(reason_codes))) if reason_codes else "threat-engine"

    subprocess.run(
        [
            "sudo",
            WRAPPER,
            "ban",
            ip,
            duration,
            reason,
        ],
        check=True,
    )
