"""
Threat intelligence enrichment.

This is what backend/main.py imports for the enrichment step of the
pipeline (AI classifier -> **threat intel enrichment** -> response engine).

For every alert it can produce:
  - ip_reputation   : "Malicious" | "Suspicious" | "Clean" | "Unknown"
  - threat_score     : 0-100 int (higher = worse)
  - mitre_technique  : "<id> - <name>" string, e.g. "T1110 - Brute Force"

Two real threat-intel sources are wired in:
  - AbuseIPDB  (IP reputation)   -> needs ABUSEIPDB_API_KEY
  - VirusTotal (file hash lookup) -> needs VIRUSTOTAL_API_KEY

Neither key is required. If a key is missing, the request fails, or the
`requests` call times out, enrichment falls back to a deterministic
heuristic (same idea as ai-model/classifier.py's "Medium" fallback) so the
API never breaks just because a teammate hasn't set up API keys yet.
"""

import hashlib
import os
import time

from dotenv import load_dotenv

load_dotenv()  # reads .env if present; no-op otherwise

try:
    from mitre_mapping import map_to_mitre
except ImportError:  # pragma: no cover - import path differs when run standalone vs. via sys.path append
    from .mitre_mapping import map_to_mitre  # type: ignore

import requests

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{hash}"

REQUEST_TIMEOUT = 5  # seconds - never let a slow/unreachable API stall alert ingestion


# ---------------------------------------------------------------------------
# IOC lookup cache
#
# AbuseIPDB's and VirusTotal's free tiers cap requests per day (AbuseIPDB:
# 1,000/day, VirusTotal public API: ~500/day, 4/min). A SOC feed can easily
# see the same noisy IP or the same malware hash dozens of times an hour, so
# without a cache a single popular IOC would burn through the daily quota by
# itself. This is a simple in-memory TTL cache: same IOC within TTL_SECONDS
# reuses the previous verdict instead of re-querying the API.
# ---------------------------------------------------------------------------

_IOC_CACHE: dict[tuple[str, str], tuple[float, tuple]] = {}
IOC_CACHE_TTL_SECONDS = 15 * 60  # 15 minutes


def _cache_get(kind: str, key: str):
    entry = _IOC_CACHE.get((kind, key))
    if entry is None:
        return None
    cached_at, value = entry
    if time.time() - cached_at > IOC_CACHE_TTL_SECONDS:
        del _IOC_CACHE[(kind, key)]
        return None
    return value


def _cache_set(kind: str, key: str, value: tuple):
    _IOC_CACHE[(kind, key)] = (time.time(), value)


def clear_ioc_cache():
    """Exposed for tests / long-running processes that want a manual reset."""
    _IOC_CACHE.clear()


# ---------------------------------------------------------------------------
# IP reputation (AbuseIPDB)
# ---------------------------------------------------------------------------

def _mock_ip_score(ip: str) -> int:
    """
    Deterministic stand-in for AbuseIPDB when no API key is configured, so
    demos/tests are reproducible: same IP always yields the same score.
    """
    if not ip:
        return 0
    digest = hashlib.sha256(ip.encode()).hexdigest()
    return int(digest[:2], 16) % 101  # 0-100


def _score_to_reputation(score: int) -> str:
    if score >= 75:
        return "Malicious"
    if score >= 25:
        return "Suspicious"
    return "Clean"


def check_ip_reputation(ip: str | None):
    """
    Returns (reputation: str, score: int) for an IP address.
    reputation is one of "Unknown" | "Clean" | "Suspicious" | "Malicious".
    Cached for IOC_CACHE_TTL_SECONDS to protect the AbuseIPDB daily quota.
    """
    if not ip:
        return "Unknown", 0

    cached = _cache_get("ip", ip)
    if cached is not None:
        return cached

    if ABUSEIPDB_API_KEY:
        try:
            resp = requests.get(
                ABUSEIPDB_URL,
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            score = int(resp.json()["data"]["abuseConfidenceScore"])
            result = (_score_to_reputation(score), score)
            _cache_set("ip", ip, result)
            return result
        except Exception as exc:  # noqa: BLE001 - any failure falls back, never breaks ingestion
            print(f"[threat-intel] WARNING: AbuseIPDB lookup failed for {ip} ({exc}); using heuristic fallback.")

    score = _mock_ip_score(ip)
    result = (_score_to_reputation(score), score)
    _cache_set("ip", ip, result)
    return result


# ---------------------------------------------------------------------------
# File hash reputation (VirusTotal)
# ---------------------------------------------------------------------------

def _mock_hash_score(file_hash: str) -> int:
    digest = hashlib.sha256(file_hash.encode()).hexdigest()
    return int(digest[:2], 16) % 101


def check_hash_reputation(file_hash: str | None):
    """
    Returns (reputation: str, score: int) for a file hash (MD5/SHA1/SHA256).
    Cached for IOC_CACHE_TTL_SECONDS to protect the VirusTotal daily/per-minute quota.
    """
    if not file_hash:
        return "Unknown", 0

    cached = _cache_get("hash", file_hash)
    if cached is not None:
        return cached

    if VIRUSTOTAL_API_KEY:
        try:
            resp = requests.get(
                VIRUSTOTAL_URL.format(hash=file_hash),
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(stats.values()) or 1
            score = int(100 * (malicious + 0.5 * suspicious) / total)
            result = (_score_to_reputation(score), score)
            _cache_set("hash", file_hash, result)
            return result
        except Exception as exc:  # noqa: BLE001
            print(f"[threat-intel] WARNING: VirusTotal lookup failed for {file_hash} ({exc}); using heuristic fallback.")

    score = _mock_hash_score(file_hash)
    result = (_score_to_reputation(score), score)
    _cache_set("hash", file_hash, result)
    return result


# ---------------------------------------------------------------------------
# Combined enrichment entry point
# ---------------------------------------------------------------------------

def enrich_alert(source: str, description: str, ip: str | None = None, hash: str | None = None):
    """
    Runs full threat-intel enrichment for one alert.

    Returns a dict:
      {
        "ip_reputation": str,
        "hash_reputation": str,
        "threat_score": int,          # combined 0-100 (max of ip/hash scores)
        "mitre_technique": str,       # "T1110 - Brute Force"
      }
    """
    ip_reputation, ip_score = check_ip_reputation(ip)
    hash_reputation, hash_score = check_hash_reputation(hash)
    technique_id, technique_name = map_to_mitre(source, description)

    return {
        "ip_reputation": ip_reputation,
        "hash_reputation": hash_reputation,
        "threat_score": max(ip_score, hash_score),
        "mitre_technique": f"{technique_id} - {technique_name}",
    }


if __name__ == "__main__":
    samples = [
        dict(source="Endpoint", description="Ransomware encryption activity detected on WEB-SRV02, mass file rename observed", ip="45.155.205.233", hash="a" * 64),
        dict(source="Firewall", description="Multiple failed login attempts detected for user jdoe followed by a successful login", ip="192.168.1.10"),
        dict(source="IDS", description="Port scan detected from internal host DB-SRV01", ip="10.0.0.5"),
        dict(source="SIEM", description="Informational: password changed successfully for user asmith"),
    ]
    for s in samples:
        result = enrich_alert(**s)
        print(result, "<-", s["description"])
