"""
Shared, in-process tracker for real external-integration call failures --
AbuseIPDB, VirusTotal, ip-api.com geolocation, and the optional Slack
webhook notifier.

Why this exists: each of those already has its own try/except that falls
back gracefully on failure (see threat-intelligence/threat_intel.py,
threat-intelligence/geo_lookup.py, and backend/main.py's Slack notifier) --
by design, a flaky/rate-limited/misconfigured external service should
never break alert ingestion. But until now that failure was only ever
printed to the backend's own console, which nobody watching the dashboard
would ever see. record_failure()/get_recent_failures() let the
Integrations tab surface it instead: a real "this fell over, here's
exactly what happened and when" signal, not just "Not configured" vs
"Connected".

Lives at the repo root (not inside backend/ or threat-intelligence/) so
every module that needs it -- backend/main.py, threat_intel.py,
geo_lookup.py -- can `import integration_health` without any of those
packages having to depend on each other.

In-memory only: a module-level dict, cleared on backend restart. That's a
deliberate scope tradeoff (same lifetime as threat_intel.py's IOC cache),
not an oversight -- a durable version would persist rows the same way
audit_log already does.
"""

import threading
from datetime import datetime, timezone

_LOCK = threading.Lock()
_MAX_FAILURES_PER_INTEGRATION = 20

# {"AbuseIPDB": [{"timestamp": iso8601 str, "detail": str, "context": str|None}, ...], ...}
_FAILURES: dict[str, list[dict]] = {}


def record_failure(integration: str, detail: str, context: str | None = None) -> None:
    """
    Appends one failure for `integration`. Best-effort: never raises, so a
    bug in health tracking itself can never take down the caller that's
    already mid-failure-handling.
    """
    try:
        with _LOCK:
            bucket = _FAILURES.setdefault(integration, [])
            bucket.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "detail": detail,
                "context": context,
            })
            del bucket[:-_MAX_FAILURES_PER_INTEGRATION]  # keep only the most recent N
    except Exception:  # noqa: BLE001
        pass


def get_recent_failures(integration: str, limit: int = 5) -> list[dict]:
    """Most recent failures first, capped at `limit`."""
    with _LOCK:
        return list(reversed(_FAILURES.get(integration, [])))[:limit]
