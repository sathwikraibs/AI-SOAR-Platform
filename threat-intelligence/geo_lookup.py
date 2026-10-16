"""
IP -> country/lat/lon geolocation, for the dashboard's Global Threat Map
(GET /threat-intel/geo in backend/main.py).

Uses ip-api.com's free, keyless endpoint (45 requests/minute is plenty for
a demo's alert volume) with the same "in-memory TTL cache + never break
the caller" pattern threat_intel.py already uses for AbuseIPDB/VirusTotal.

Private/loopback/link-local addresses (10.x, 172.16-31.x, 192.168.x,
127.x, ...) can't be geolocated by a public API -- they're skipped and
reported as "Internal Network" with no coordinates, rather than sent to
ip-api.com or silently dropped.
"""

import ipaddress
import time

import requests

try:
    # See threat_intel.py's identical shim for why this is optional --
    # only importable when the repo root is already on sys.path.
    from integration_health import record_failure
except ImportError:  # pragma: no cover
    def record_failure(*_args, **_kwargs):  # type: ignore
        pass

GEO_API_URL = "http://ip-api.com/json/{ip}"
REQUEST_TIMEOUT = 4  # seconds - a slow lookup should never stall the map endpoint

_GEO_CACHE: dict[str, tuple[float, dict | None]] = {}
GEO_CACHE_TTL_SECONDS = 60 * 60  # 1 hour - geolocation for a given IP essentially never changes


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a real IP (e.g. malformed) -> treat like "can't geolocate", don't call the API
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def geolocate_ip(ip: str | None) -> dict | None:
    """
    Returns {"country": str, "lat": float, "lon": float} for a public IP,
    {"country": "Internal Network", "lat": None, "lon": None} for a
    private/loopback/reserved one, or None if the lookup failed entirely
    (API unreachable, rate-limited, or the IP couldn't be resolved).
    """
    if not ip:
        return None

    if ip in _GEO_CACHE:
        cached_at, value = _GEO_CACHE[ip]
        if time.time() - cached_at <= GEO_CACHE_TTL_SECONDS:
            return value
        del _GEO_CACHE[ip]

    if _is_private(ip):
        result = {"country": "Internal Network", "lat": None, "lon": None}
        _GEO_CACHE[ip] = (time.time(), result)
        return result

    try:
        resp = requests.get(
            GEO_API_URL.format(ip=ip),
            params={"fields": "status,country,lat,lon"},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            reason = data.get("message", "unknown reason")
            print(f"[geo-lookup] WARNING: ip-api.com returned status={data.get('status')} for {ip} ({reason})")
            record_failure("IP Geolocation", reason, context=f"IP: {ip}")
            _GEO_CACHE[ip] = (time.time(), None)
            return None
        result = {"country": data["country"], "lat": data["lat"], "lon": data["lon"]}
        _GEO_CACHE[ip] = (time.time(), result)
        return result
    except Exception as exc:  # noqa: BLE001 - a geolocation failure should never break the map endpoint
        print(f"[geo-lookup] WARNING: geolocation failed for {ip} ({exc})")
        record_failure("IP Geolocation", str(exc), context=f"IP: {ip}")
        _GEO_CACHE[ip] = (time.time(), None)
        return None
