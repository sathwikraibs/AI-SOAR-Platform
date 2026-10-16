"""
Lets the watcher know which detection rules are currently enabled.

detection-agent is deliberately a fully decoupled process -- it has no
database access, it only talks to the backend over HTTP (POST /alerts).
So "toggling a rule off" from the dashboard can't reach into this
process directly; instead this module polls GET /detection-rules on the
backend and caches the result briefly, and rules.py / rules_target.py
check is_enabled(rule_key) before turning a match into a finding.

Fails OPEN on purpose: if the backend is briefly unreachable, every rule
is treated as enabled rather than silently going dark. A demo where
detection stops because of a transient network hiccup is worse than one
where a rule you meant to disable fires once more before the next
successful poll.
"""

import time

import requests

API_BASE = "http://localhost:8000"
DETECTION_RULES_URL = f"{API_BASE}/detection-rules"
REFRESH_SECONDS = 5  # how long a cached result is trusted before re-polling
REQUEST_TIMEOUT = 3

_cache: dict[str, bool] = {}
_last_fetch = 0.0
_warned = False


def _refresh() -> None:
    global _cache, _last_fetch, _warned
    try:
        resp = requests.get(DETECTION_RULES_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        _cache = {rule["key"]: rule["enabled"] for rule in resp.json()}
        _last_fetch = time.time()
        _warned = False
    except (requests.RequestException, ValueError, KeyError):
        # Leave the previous cache in place (or empty, meaning "enabled" by
        # default via is_enabled()'s fallback) and try again next call.
        if not _warned:
            _warned = True
            print(
                f"[detection-agent] WARNING: couldn't reach {DETECTION_RULES_URL} to check "
                "rule enable/disable state -- treating all rules as enabled until it's reachable."
            )


def is_enabled(rule_key: str | None) -> bool:
    """
    True if this rule should currently fire. A finding with no rule_key
    (shouldn't normally happen) is always allowed through. Unknown keys
    (a finding kind not listed on the dashboard's Detection Rules tab)
    also default to enabled -- only an explicit disabled=True in the
    backend's response suppresses a rule.
    """
    if rule_key is None:
        return True
    if time.time() - _last_fetch > REFRESH_SECONDS:
        _refresh()
    return _cache.get(rule_key, True)
