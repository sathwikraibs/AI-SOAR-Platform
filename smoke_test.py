"""
Quick check that the backend's new endpoints work. Run it with the backend started:

    python smoke_test.py                       # default http://localhost:8000
    python smoke_test.py http://localhost:8000

It changes nothing permanently: switches it flips are put back, and the one
blocklist entry it adds is removed again. It creates no alerts and no devices.
"""
import sys

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if detail and not ok else ""))


def get(path, **kw):
    return requests.get(BASE + path, timeout=15, **kw)


def post(path, body=None):
    return requests.post(BASE + path, json=body, timeout=15)


try:
    r = get("/")
except requests.RequestException as exc:
    sys.exit(f"Cannot reach the backend at {BASE} ({exc}). Start it first: python -m uvicorn backend.main:app --reload")
check("backend is up", r.status_code == 200, r.text)

for path in ["/alerts", "/assets", "/agents", "/blocklist", "/detection-rules", "/ransomware/status", "/vpn-activity", "/blocklist/custom", "/target-config", "/blocklist/export"]:
    r = get(path)
    check(f"GET {path}", r.status_code == 200, f"{r.status_code} {r.text[:120]}")

r = get("/ransomware/status").json()
check("ransomware status shape", {"active", "total", "incidents"} <= set(r), r)

r = get("/vpn-activity").json()
check("vpn-activity shape", {"auto_block", "rows"} <= set(r), r)

keys = {x["key"] for x in get("/detection-rules").json()}
for k in ["anonymizer_ip_detected", "sysmon_policy_violation", "sysmon_malicious_website", "ransomware_activity", "anonymizer_ip_block"]:
    check(f"detection rule {k} listed", k in keys)

# VPN auto-block switch
original = get("/settings/vpn-block").json().get("auto_block", True)
try:
    for want in (False, True):
        r = post("/settings/vpn-block", {"enabled": want})
        got = get("/settings/vpn-block").json().get("auto_block")
        check(f"vpn auto-block set to {want}", r.status_code == 200 and got is want, f"{r.status_code} {got}")
        cfg = get("/target-config").json()
        check(f"target-config follows ({want})", cfg.get("auto_block") is want, cfg)
finally:
    post("/settings/vpn-block", {"enabled": original})

# Custom blocklist entry (documentation range, harmless)
entry = "198.18.77.0/24"
r = post("/blocklist/custom", {"entry": entry, "category": "vpn", "label": "smoke test"})
check("add custom blocklist entry", r.status_code == 200, f"{r.status_code} {r.text[:120]}")
m = get("/blocklist/check", params={"ip": "198.18.77.5"}).json().get("match")
check("added range is matched", bool(m), m)
r = requests.delete(BASE + "/blocklist/custom", params={"entry": entry}, timeout=15)
check("remove custom entry", r.status_code == 200, r.text)
m = get("/blocklist/check", params={"ip": "198.18.77.5"}).json().get("match")
check("removed range no longer matched", not m, m)
r = post("/blocklist/custom", {"entry": "10.0.0.0/8", "category": "vpn", "label": "should be refused"})
check("private range is refused", r.status_code == 422, f"{r.status_code}")

# Master monitoring switch
original = get("/settings/monitoring").json().get("enabled", True)
try:
    for want in (False, True):
        post("/settings/monitoring", {"enabled": want})
        got = get("/settings/monitoring").json().get("enabled")
        check(f"monitoring master switch {want}", got is want, got)
finally:
    post("/settings/monitoring", {"enabled": original})

# Per-device switch, only if a device already exists
agents = get("/agents").json()
if agents:
    host = agents[0]["hostname"]
    cur = agents[0].get("monitoring_enabled", True)
    try:
        post(f"/agents/{host}/monitoring", {"enabled": not cur})
        new = [a for a in get("/agents").json() if a["hostname"] == host][0]
        check(f"device switch flips for {host}", new.get("monitoring_enabled") is (not cur), new)
    finally:
        post(f"/agents/{host}/monitoring", {"enabled": cur})
else:
    print("[skip] no devices connected yet, so the per-device switch was not tested")

print()
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
