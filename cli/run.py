# cli/run.py

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
import pathlib
import urllib.request

from threat_engine.validator import validate_and_sort
from threat_engine.engine import decide
from threat_engine.explain import explain, explain_structured
from threat_engine.errors import ThreatEngineError, EnforcementError
from threat_engine.persistence import DecisionStore
from threat_engine.explain_cached import explain_cached, explain_cached_structured
from threat_engine.enforce import enforce_crowdsec, should_enforce, format_enforcement_preview
from threat_engine.policies import DECISION_TTLS

###################
##### Helpers #####
###################

def load_input(path_or_url: str) -> dict:
    if path_or_url.startswith(("http://", "https://")):
        with urllib.request.urlopen(path_or_url) as resp:
            return json.load(resp)

    path = pathlib.Path(path_or_url)
    if not path.exists():
        raise ThreatEngineError(f"Input not found: {path}")

    with path.open() as f:
        return json.load(f)

def write_output(decisions: list, output: str | None):
    if not output:
        return

    try:
        with open(output, "w") as f:
            json.dump(decisions, f, indent=2)
    except Exception as e:
        raise ThreatEngineError(f"Failed to write output: {e}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Threat Decision Engine Runner"
    )

    parser.add_argument(
        "--mode",
        choices=["dry-run", "explain", "enforce"],
        default="dry-run",
        help="Execution mode (default: dry-run)"
    )

    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm enforcement actions"
    )

    parser.add_argument(
        "--input",
        help="Path or URL to threat API JSON"
    )

    parser.add_argument(
        "--output",
        help="Write decisions to file (JSON)"
    )

    parser.add_argument(
        "--limit",
        type=int,
        help="Process only the top N threats after sorting"
    )

    parser.add_argument(
        "--ip",
        help="Filter explanations to this IP"
    )

    parser.add_argument(
        "--scenario",
        help="Filter to threats containing this scenario name"
    )


    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Exit non-zero if any decision fails"
    )

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text"
    )

    return parser.parse_args()

###################
### TTL Helpers ###
###################


def ensure_ttl(decision: dict):
    """Force TTLs from DECISION_TTLS for enforceable decisions."""
    ttl = DECISION_TTLS.get(decision["decision"])
    if not ttl:
        decision["expires_at"] = None
        decision.pop("ttl_seconds", None)
        return

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    decision["expires_at"] = expires_at.isoformat()
    decision["ttl_seconds"] = ttl

###############
#### Main #####
###############

def main():
    args = parse_args()

    try:
        store = DecisionStore()

        if args.mode == "explain" and args.ip:
            db_decision = store.get_active_decision(args.ip)

            if not db_decision:
                print(f"No active decision found for IP {args.ip}")
                return

            if args.format == "json":
                print(json.dumps(
                    explain_cached_structured(db_decision),
                    indent=2
                ))
            else:
                print(explain_cached(db_decision))

            return

        if not args.input:
            raise ThreatEngineError(
                "--input is required unless using --mode explain with --ip"
            )

        data = load_input(args.input)
        threats = validate_and_sort(data["threats"])

        new_threats = []
        for t in threats:
            existing = store.get_active_decision(t["ip"])
            if existing and existing["decision"] == "PERM_BAN":
                continue
            new_threats.append(t)
            if args.limit and len(new_threats) >= args.limit:
                break

        threats = new_threats

        decisions = []

        for t in threats:
            existing = store.get_active_decision(t["ip"])

            if existing and existing["decision"] == "PERM_BAN":
                continue

            current_strikes = store.get_strikes(t["ip"])
            predicted_strikes = current_strikes + 1

            # first pass: predict post-strike decision to determine enforcement necessity
            predicted = decide(t, strike_count=predicted_strikes, existing_decision=existing)
            ensure_ttl(predicted)

            if existing and not should_enforce(existing, predicted):
                continue

            decision = decide(
                t,
                strike_count=current_strikes + 1,
                existing_decision=existing
            )

            if not existing or decision["decision"] != existing["decision"]:
                strike_count = store.record_strike(t["ip"])
            else:
                strike_count = current_strikes

            decision["strike_count"] = strike_count

            ensure_ttl(decision)

            if decision["decision"] in ("TEMP_BAN", "PERM_BAN"):
                store.remove_lower_decisions(
                    decision["ip"],
                    decision["decision"]
                )

            store.store_decision(decision)
            decisions.append(decision)


        if args.mode == "explain":
            for d in decisions:
                if args.format == "json":
                    print(json.dumps(explain_structured(d), indent=2))
                else:
                    print(explain(d))
            return

        if args.mode == "enforce":
            if not args.yes:
                print(format_enforcement_preview(decisions))
                raise EnforcementError(
                    "Refusing to enforce decisions without --yes confirmation"
                )

            to_enforce = [
                d for d in decisions
                if d["decision"] in ("TEMP_BAN", "PERM_BAN")
            ]

            failed = []

            for d in to_enforce:
                try:
                    enforce_crowdsec(d)

                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(
                        f"[{now}] IP: {d['ip']} "
                        f"- Confidence: {d['confidence']['score']} "
                        f"- Severity: {d['evidence']['severity']} "
                        f"- Decision: {d['decision']}"
                    )

                except EnforcementError as e:
                    failed.append((d["ip"], str(e)))
                    if args.fail_on_error:
                        raise

            if failed:
                print("\nEnforcement failures:")
                for ip, err in failed:
                    print(f" - {ip}: {err}")


            print(f"Evaluated {len(decisions)} threats, enforced {len(to_enforce)}")
            store.set_metadata("last_updated", datetime.now(timezone.utc).isoformat())

            return

        if args.mode == "dry-run":
            print(f"Dry run: {len(decisions)} decisions generated")
            for d in decisions:
                print(
                    f"- {d['decision']} {d['ip']} "
                    f"(confidence={d['confidence']['score']}, "
                    f"severity={d['evidence']['severity']})"
                )

        filtered = decisions

        if args.ip:
            filtered = [d for d in filtered if d["ip"] == args.ip]

        if args.scenario:
            filtered = [
                d for d in filtered
                if any(s["name"] == args.scenario for s in d.get("scenarios", []))
            ]

        write_output(filtered, args.output)

    except ThreatEngineError as e:
        print(f"Engine error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
