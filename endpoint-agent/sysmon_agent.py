"""
Sysmon endpoint agent.

Runs on a device you want to protect. It reads that device's Sysmon events,
reports every event to the SOAR backend (so the dashboard's Assets tab shows
a live activity feed for the device), and raises an alert (POST /alerts) when
an event matches a detection rule. Alerts then go through the normal pipeline:
AI classifier -> threat intel -> risk score -> automated response.

Real device (Windows, Sysmon installed, Administrator prompt):
    python endpoint-agent/sysmon_agent.py --backend http://<soar-server>:8000

Demo without Sysmon, any OS (pretend to be one or several devices):
    python endpoint-agent/sysmon_agent.py --simulate --hostname DEMO-PC-1 --attack all
    python endpoint-agent/sysmon_agent.py --simulate --hostname DEMO-PC-2 --attack tor,lsass

See endpoint-agent/README.md.
"""

import argparse
import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone

import requests

import simulator
import sysmon_events
from sysmon_policy import PolicyTracker, load_policy
from sysmon_rules import SysmonAnalyzer

AGENT_VERSION = "1.1"
HEARTBEAT_SECONDS = 3      # also how quickly an ON/OFF switch from the dashboard takes effect
REQUEST_TIMEOUT = 5
RULE_CACHE_SECONDS = 15
SOURCE = "Sysmon"
LOG = "[endpoint-agent]"


def local_ip() -> str | None:
    """The address this device uses to reach the network (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


class Backend:
    def __init__(self, base_url: str, dry_run: bool, token: str = ""):
        self.base = base_url.rstrip("/")
        self.dry_run = dry_run
        self.headers = {"X-Agent-Token": token} if token else {}
        self.monitoring = True      # last answer from the dashboard's ON/OFF switches (True until told otherwise)
        self._ip_cache: dict[str, dict | None] = {}
        self._rules: dict[str, bool] = {}
        self._rules_at = 0.0
        self._warned = False

    def _warn(self, what: str, exc: Exception):
        if not self._warned:
            print(f"{LOG} WARNING: could not reach the backend for {what} ({exc}). Is it running at {self.base}? Will keep retrying.")
            self._warned = True

    def _post(self, path: str, payload: dict):
        if self.dry_run:
            return None
        try:
            resp = requests.post(self.base + path, json=payload, headers=self.headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 401:
                if not self._warned:
                    print(f"{LOG} ERROR: the backend refused the agent token (401). Use --token (or SOAR_AGENT_TOKEN) equal to the backend's SOAR_AGENT_TOKEN.")
                    self._warned = True
                return None
            resp.raise_for_status()
            self._warned = False
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            self._warn(path, exc)
            return None

    def heartbeat(self, hostname, ip, sysmon_status, owner=None, usage=None):
        """Reports in, and learns whether monitoring is currently switched on for this device."""
        result = self._post("/agents/heartbeat", {
            "hostname": hostname, "ip": ip, "os": f"{platform.system()} {platform.release()}",
            "agent_version": AGENT_VERSION, "sysmon_status": sysmon_status,
            "owner": owner, "usage": usage,
        })
        if isinstance(result, dict) and "monitoring" in result:
            self.monitoring = bool(result["monitoring"])
        return result

    def send_events(self, hostname, items):
        if items:
            self._post("/agents/events", {"hostname": hostname, "events": items})

    def send_alert(self, hostname, finding):
        payload = {
            "source": SOURCE,
            "description": f"[{hostname}] {finding['description']}",
            "ip": finding.get("ip"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule_key": finding["rule_key"],
            "host": hostname,
        }
        if self.dry_run:
            print(f"{LOG} (dry-run) ALERT {finding['rule_key']}: {payload['description']}")
            return
        alert = self._post("/alerts", payload)
        if alert and alert.get("ignored"):
            print(f"{LOG} alert dropped by the backend ({alert.get('reason')})")
        elif alert:
            print(f"{LOG} ALERT SENT id={alert.get('id')} severity={alert.get('severity')} "
                  f"risk={alert.get('risk_score')} response={alert.get('response_status')}")
            print(f"{LOG}   {payload['description']}")

    # Used by the analyzer.
    def check_ip(self, ip: str):
        if ip in self._ip_cache or self.dry_run:
            return self._ip_cache.get(ip)
        try:
            resp = requests.get(self.base + "/blocklist/check", params={"ip": ip}, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            match = resp.json().get("match")
        except requests.RequestException:
            return None  # don't cache failures
        self._ip_cache[ip] = match
        return match

    def is_enabled(self, rule_key: str) -> bool:
        if self.dry_run:
            return True
        if time.monotonic() - self._rules_at > RULE_CACHE_SECONDS:
            try:
                resp = requests.get(self.base + "/detection-rules", timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                self._rules = {r["key"]: r["enabled"] for r in resp.json()}
            except requests.RequestException:
                pass
            self._rules_at = time.monotonic()
        return self._rules.get(rule_key, True)


def process(events, analyzer, backend, hostname):
    """Analyze events, report the activity feed, raise alerts."""
    items, findings = [], []
    for ev in events:
        activity, found = analyzer.analyze(ev)
        if activity:
            items.append(activity)
        findings.extend(found)
    backend.send_events(hostname, items)
    for f in findings:
        backend.send_alert(hostname, f)
    return len(items), len(findings)


def parse_args():
    p = argparse.ArgumentParser(description="Sysmon endpoint agent for the AI-SOAR platform")
    p.add_argument("--backend", default="http://localhost:8000", help="SOAR backend URL (default %(default)s)")
    p.add_argument("--hostname", default=socket.gethostname(), help="name shown in the dashboard (default: this computer's name)")
    p.add_argument("--simulate", action="store_true", help="use simulated Sysmon events instead of the real log")
    p.add_argument("--attack", default="", help="with --simulate: scenarios to play (all, or e.g. tor,lsass). Choices: " + ", ".join(simulator.SCENARIOS))
    p.add_argument("--interval", type=float, default=1.0, help="seconds between polls (default 1)")
    p.add_argument("--backfill", type=int, default=0, help="real mode: also replay the last N existing events at start")
    p.add_argument("--dry-run", action="store_true", help="don't contact the backend; print what would be sent")
    p.add_argument("--once", action="store_true", help="exit after the attack scenarios finish (simulate mode)")
    p.add_argument("--owner", default="", help="whose device this is, shown in the dashboard's Assets tab (e.g. --owner \"Priya Sharma\")")
    p.add_argument("--token", default=os.environ.get("SOAR_AGENT_TOKEN", ""), help="shared secret, if the backend sets SOAR_AGENT_TOKEN (or set that variable here)")
    p.add_argument("--policy", default=None, help="path to a policy.json (default: the one next to this script)")
    hours = p.add_mutually_exclusive_group()
    hours.add_argument("--ignore-work-hours", action="store_true", help="apply the activity limits at any time of day (default for --simulate)")
    hours.add_argument("--respect-work-hours", action="store_true", help="no effect (usage is always counted); kept so older commands still run")
    return p.parse_args()


def run_simulated(args, backend, analyzer, tracker):
    try:
        attacks = simulator.expand_attack_arg(args.attack) if args.attack else []
    except ValueError as exc:
        sys.exit(f"{LOG} {exc}")
    # Each scenario is a list of steps; queue them one step per poll after a short warm-up of normal activity.
    queue = [step for name in attacks for step in simulator.scenario_events(name)]
    print(f"{LOG} SIMULATED mode as '{args.hostname}'. Scenarios: {', '.join(attacks) or 'none (normal activity only)'}")
    warmup = 2 if queue else 0
    tick = 0
    paused = False
    while True:
        backend.heartbeat(args.hostname, local_ip(), "Simulated", args.owner or None, tracker.usage_summary())
        if not backend.monitoring:
            if not paused:
                print(f"{LOG} MONITORING PAUSED from the dashboard: nothing is generated or sent until it is switched back on.")
                paused = True
            time.sleep(args.interval)
            continue
        if paused:
            print(f"{LOG} monitoring resumed.")
            paused = False
        events = simulator.benign_events(2)
        if tick >= warmup and queue:
            events += queue.pop(0)
            if not queue and args.once:
                process(events, analyzer, backend, args.hostname)
                backend.heartbeat(args.hostname, local_ip(), "Simulated", args.owner or None, tracker.usage_summary())
                print(f"{LOG} scenarios finished.")
                return
        n, a = process(events, analyzer, backend, args.hostname)
        print(f"{LOG} {n} events reported, {a} alert(s) raised")
        tick += 1
        time.sleep(args.interval)


def run_real(args, backend, analyzer, tracker):
    if not sysmon_events.sysmon_installed():
        try:
            sysmon_events._run_wevtutil(["gl", sysmon_events.SYSMON_LOG])
        except sysmon_events.SysmonReadError as exc:
            sys.exit(f"{LOG} {exc}")
    print(f"{LOG} Reading Sysmon on '{args.hostname}' -> {backend.base}")
    # Find out first whether monitoring is on, so nothing is read or sent while it is off.
    backend.heartbeat(args.hostname, local_ip(), "Running", args.owner or None, tracker.usage_summary())
    last_beat = time.monotonic()
    try:
        if backend.monitoring and args.backfill:
            history = sysmon_events.read_recent_events(args.backfill)
            last = history[-1]["record_id"] if history else 0
            process(history, analyzer, backend, args.hostname)
        else:
            last = sysmon_events.latest_record_id()
    except sysmon_events.SysmonReadError as exc:
        sys.exit(f"{LOG} {exc}")
    paused = False
    while True:
        if time.monotonic() - last_beat >= HEARTBEAT_SECONDS:
            backend.heartbeat(args.hostname, local_ip(), "Running", args.owner or None, tracker.usage_summary())
            last_beat = time.monotonic()
        if not backend.monitoring:
            if not paused:
                print(f"{LOG} MONITORING PAUSED from the dashboard: the Sysmon log is not being read.")
                paused = True
            time.sleep(min(args.interval, HEARTBEAT_SECONDS))
            continue
        try:
            if paused:
                # Skip everything that happened while monitoring was off; it is never read or sent.
                last = sysmon_events.latest_record_id()
                paused = False
                print(f"{LOG} monitoring resumed (activity during the pause was not recorded).")
            events = sysmon_events.read_new_events(last)
        except sysmon_events.SysmonReadError as exc:
            print(f"{LOG} WARNING: {exc}")
            time.sleep(args.interval)
            continue
        if events:
            last = max(e["record_id"] or 0 for e in events + [{"record_id": last}])
            n, a = process(events, analyzer, backend, args.hostname)
            print(f"{LOG} {n} events reported, {a} alert(s) raised")
        time.sleep(args.interval)


def main():
    args = parse_args()
    backend = Backend(args.backend, args.dry_run, args.token)
    # In simulate mode the activity limits apply at any hour by default, so a demo works on a weekend.
    ignore_hours = args.ignore_work_hours or (args.simulate and not args.respect_work_hours)
    tracker = PolicyTracker(policy=load_policy(args.policy), ignore_work_hours=ignore_hours)
    analyzer = SysmonAnalyzer(check_ip=backend.check_ip, is_enabled=backend.is_enabled, tracker=tracker)
    try:
        if args.simulate:
            run_simulated(args, backend, analyzer, tracker)
        else:
            run_real(args, backend, analyzer, tracker)
    except KeyboardInterrupt:
        print(f"\n{LOG} stopped.")


if __name__ == "__main__":
    main()
