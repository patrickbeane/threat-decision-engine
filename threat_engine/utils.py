# threat_engine/utils.py

def format_duration(seconds: int | None) -> str:
    """Convert seconds to human-readable string"""
    if seconds is None:
        return "perm"

    if seconds >= 86400:
        days = seconds // 86400
        return f"{days}d"
    elif seconds >= 3600:
        hours = seconds // 3600
        return f"{hours}h"
    elif seconds >= 60:
        minutes = seconds // 60
        return f"{minutes}m"
    return f"{seconds}s"
