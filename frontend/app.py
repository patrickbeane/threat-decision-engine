from flask import Flask, render_template, jsonify, request
from datetime import datetime, timezone
from threat_engine.persistence import DecisionStore
from threat_engine.explain import explain_structured

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
app.jinja_env.cache = {}

ds = DecisionStore()

# Helpers

def human_delta(iso_ts: str) -> str:
    if not iso_ts:
        return "unknown"

    ts = datetime.fromisoformat(iso_ts)
    now = datetime.now(timezone.utc)
    diff = now - ts

    minutes = diff.total_seconds() // 60
    hours = minutes // 60
    days = hours // 24

    if minutes < 1:
        return "just now"
    if minutes == 1:
        return "1 minute ago"
    if minutes < 60:
        return f"{int(minutes)} minutes ago"
    if hours == 1:
        return "1 hour ago"
    if hours < 24:
        return f"{int(hours)} hours ago"
    if days == 1:
        return "1 day ago"
    return f"{int(days)} days ago"

def human_ttl(seconds: int | None, precise: bool = False) -> str:
    if seconds is None:
        return "∞"

    if seconds < 60:
        return "<1m"

    minutes = seconds // 60
    if not precise:
        if minutes < 60:
            return f"{minutes}m"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h"
        return f"{hours // 24}d"

    if minutes < 60:
        return f"{minutes}m"

    hours, rem_m = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {rem_m}m"

    days, rem_h = divmod(hours, 24)
    return f"{days}d {rem_h}h"

def paginate(items, page, per_page=10):
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], len(items)

# Flask Dashboard

@app.route("/")
def dashboard():
    decisions = ds.get_active_decisions(limit=500)

    for d in decisions:
        d["ttl_display"] = human_ttl(d["ttl_seconds"])

    perm = [d for d in decisions if d["decision"] == "PERM_BAN"]
    temp = [d for d in decisions if d["decision"] == "TEMP_BAN"]
    watch = [d for d in decisions if d["decision"] == "WATCH"]

    perm.sort(key=lambda d: d["ttl_seconds"], reverse=True)
    temp.sort(key=lambda d: d["ttl_seconds"], reverse=True)
    watch.sort(key=lambda d: d["ttl_seconds"], reverse=True)

    perm_page = int(request.args.get("perm_page", 1))
    temp_page = int(request.args.get("temp_page", 1))
    watch_page = int(request.args.get("watch_page", 1))

    perm_slice, perm_total = paginate(perm, perm_page)
    temp_slice, temp_total = paginate(temp, temp_page)
    watch_slice, watch_total = paginate(watch, watch_page)

    last_updated = ds.get_metadata("last_updated")
    delta = human_delta(last_updated)

    return render_template(
        "dashboard.html",
        perm=perm_slice,
        temp=temp_slice,
        watch=watch_slice,

        perm_page=perm_page,
        temp_page=temp_page,
        watch_page=watch_page,

        perm_total=perm_total,
        temp_total=temp_total,
        watch_total=watch_total,

        per_page=10,

        delta=delta
    )

@app.route("/explain/<ip>")
def explain(ip):
    decision = ds.get_active_decision(ip)

    if not decision:
        return "No active decision for this IP", 404

    explained = explain_structured(decision)

    explained["mitre_tactics"] = [
        t for t in decision.get("mitre_tactics", []) 
        if t and t != "Unknown"
    ]

    explained["mitre_techniques"] = [
        t for t in decision.get("mitre_techniques", [])
        if t
    ]

    explained["ttl_display"] = human_ttl(decision.get("ttl_seconds"), precise=True)

    return render_template("explain.html", decision=explained)

@app.route("/api/decisions")
def api_dashboard():
    decisions = ds.get_active_decisions()
    return jsonify(decisions)

@app.route("/api/explain/<ip>")
def api_explain(ip):
    decision = ds.get_active_decision(ip)
    if not decision:
        return jsonify({"error": "No active decision for this IP"}), 404

    return jsonify(decision)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
