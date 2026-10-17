"""
Acceptable-use policy checks for a monitored device.

What Sysmon can see: every DNS lookup (event 22: which domain, which program)
and every program that starts (event 1). That is enough to answer the questions
an office cares about, as long as the limits are understood:

  * Websites are known by DOMAIN (youtube.com), not by page or video title.
  * "Time on a site" is estimated: a minute counts as active when the device
    looked up a domain of that category during that minute. It is an
    approximation, not a stopwatch, and it undercounts rather than overcounts.
  * A browser using encrypted DNS (DNS-over-HTTPS) hides its lookups from
    Sysmon. Turn that off in the browser for the demo if lookups do not show.

Two kinds of finding come out of here:

  sysmon_malicious_website   the device looked up a domain on the malicious-sites list
  sysmon_policy_violation    too many active minutes today on a category (streaming,
                             social media, games), or a VPN / Tor
                             client was started on the device

Every finding tells the reader what action to take ("Recommended action: ...").

The limits, categories, domains and work hours live in policy.json next to this
file; edit it freely (it is read when the agent starts). Without that file the
built-in defaults below are used.
"""

import json
import os
from datetime import datetime

RULE_MALICIOUS_SITE = "sysmon_malicious_website"
RULE_POLICY = "sysmon_policy_violation"

_HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_FILE = os.path.join(_HERE, "policy.json")
MALICIOUS_FILES = [
    os.path.join(_HERE, "malicious_domains.txt"),
    os.path.join(_HERE, "malicious_domains_feed.txt"),   # written by update_malicious_domains.py
]

DEFAULT_POLICY = {
    "categories": {
        "streaming": {
            "label": "Streaming video",
            "limit_minutes": 30,
            "domains": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "netflix.com", "nflxvideo.net",
                        "primevideo.com", "hotstar.com", "twitch.tv", "disneyplus.com"],
        },
        "social": {
            "label": "Social media",
            "limit_minutes": 30,
            "domains": ["facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "twitter.com", "x.com",
                        "tiktok.com", "snapchat.com", "reddit.com", "redd.it"],
        },
        "games": {
            "label": "Games",
            "limit_minutes": 20,
            "domains": ["steampowered.com", "steamcontent.com", "epicgames.com", "roblox.com", "riotgames.com"],
        },
    },
    # Programs that should not be running on a work device at all. One start = one finding.
    "forbidden_programs": {
        "label": "VPN / Tor client",
        "programs": ["protonvpn.exe", "protonvpn.client.exe", "openvpn.exe", "openvpn-gui.exe", "wireguard.exe",
                     "nordvpn.exe", "expressvpn.exe", "windscribe.exe", "tor.exe", "psiphon3.exe"],
    },
}

# The action a reader should take, per kind of finding.
PROGRAM_REALERT_SECONDS = 120   # a VPN / Tor client started again within this time of its last alert is not alerted twice
ACTION_SOFT = "Recommended action: send the employee a policy reminder and notify their manager."
ACTION_PROGRAM = "Recommended action: ask the employee why a VPN or Tor client is installed, and review the device's recent activity."
ACTION_MALICIOUS = "Recommended action: block the domain, review what the device downloaded, and run a full antivirus scan."


def _clean_domain(name) -> str:
    return str(name or "").strip().lower().rstrip(".")


def _in_domain_list(domain: str, mapping: dict):
    """Looks up a domain and its parents: 'rr4---sn.googlevideo.com' matches 'googlevideo.com'."""
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        key = ".".join(parts[i:])
        if key in mapping:
            return mapping[key]
    return None


def load_policy(path: str | None = None) -> dict:
    path = path or POLICY_FILE
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("categories"), dict):
            merged = dict(DEFAULT_POLICY)
            merged.update(data)
            return merged
    except (OSError, ValueError):
        pass
    return DEFAULT_POLICY


def load_malicious_domains() -> set[str]:
    domains: set[str] = set()
    for path in MALICIOUS_FILES:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip().lower()
                    if line and " " not in line and "." in line:
                        domains.add(line.rstrip("."))
        except OSError:
            continue
    return domains


def _minutes(hhmm: str) -> int:
    h, m = str(hhmm).split(":")
    return int(h) * 60 + int(m)


class PolicyTracker:
    """
    Keeps today's active minutes per category for one device and decides when
    to raise a finding. One instance per agent.
    """

    def __init__(self, policy: dict | None = None, malicious: set[str] | None = None, ignore_work_hours: bool = False):
        self.policy = policy or load_policy()
        self.malicious = malicious if malicious is not None else load_malicious_domains()
        self._malicious_map = dict.fromkeys(self.malicious, True)
        self.ignore_work_hours = ignore_work_hours
        self._domain_to_cat: dict[str, str] = {}
        for key, cat in self.policy.get("categories", {}).items():
            for d in cat.get("domains", []):
                self._domain_to_cat[_clean_domain(d)] = key
        forbidden = self.policy.get("forbidden_programs") or {}
        self._programs = {str(p).lower() for p in forbidden.get("programs", [])}
        self._programs_label = forbidden.get("label", "VPN / Tor client")
        self._date = None
        self._minutes: dict[str, set[str]] = {}
        self._level_alerted: dict[str, int] = {}     # category -> highest limit multiple already alerted today
        self._top_domain: dict[str, dict[str, int]] = {}
        self._malicious_alerted: set[str] = set()
        self._programs_alerted: dict[str, datetime] = {}   # program -> when it last raised an alert

    # -- time ---------------------------------------------------------------
    def _local(self, when: datetime) -> datetime:
        return when.astimezone() if when.tzinfo else when

    def _roll_day(self, local: datetime) -> None:
        today = local.date().isoformat()
        if today != self._date:
            self._date = today
            self._minutes = {}
            self._level_alerted = {}
            self._top_domain = {}
            self._malicious_alerted = set()
            self._programs_alerted = {}

    def in_work_hours(self, local: datetime) -> bool:
        # No time-of-day restriction: usage is counted around the clock, every day.
        return True

    # -- observations --------------------------------------------------------
    def category_of(self, domain: str):
        """(category key, label) for a domain, or (None, None)."""
        key = _in_domain_list(_clean_domain(domain), self._domain_to_cat)
        if key is None:
            return None, None
        return key, self.policy["categories"][key].get("label", key)

    def observe_domain(self, when: datetime, domain: str, program: str = "") -> tuple[str | None, list[tuple[str, str]]]:
        """
        A DNS lookup. Returns (category label or None, findings), where a finding
        is (rule_key, text).
        """
        domain = _clean_domain(domain)
        if not domain:
            return None, []
        local = self._local(when)
        self._roll_day(local)
        findings: list[tuple[str, str]] = []

        if _in_domain_list(domain, self._malicious_map) and domain not in self._malicious_alerted:
            self._malicious_alerted.add(domain)
            findings.append((
                RULE_MALICIOUS_SITE,
                f"Malicious website visited: the device looked up known-malicious domain {domain}"
                f"{' (from ' + program + ')' if program else ''}. {ACTION_MALICIOUS}",
            ))

        key, label = self.category_of(domain)
        if key is None:
            return None, findings
        cat = self.policy["categories"][key]
        counts = self._top_domain.setdefault(key, {})
        counts[domain] = counts.get(domain, 0) + 1

        if not self.in_work_hours(local):
            return label, findings
        minute = local.strftime("%H:%M")
        mins = self._minutes.setdefault(key, set())
        mins.add(minute)

        limit = int(cat.get("limit_minutes", 0)) or 1
        level = (len(mins) - 1) // limit       # 1 = over the limit, 2 = over double the limit
        if 1 <= level <= 2 and level > self._level_alerted.get(key, 0):
            self._level_alerted[key] = level
            top = max(counts, key=counts.get)
            more = " (double the limit)" if level == 2 else ""
            findings.append((
                RULE_POLICY,
                f"Acceptable-use policy violation: {label.lower()} for {len(mins)} minutes today on this device"
                f"{more}, over the {limit}-minute daily limit; most visited {top}. {ACTION_SOFT}",
            ))
        return label, findings

    def observe_process(self, when: datetime, program: str) -> list[tuple[str, str]]:
        """A program started. Flags VPN / Tor clients; the same program raises a new alert only if it is
        started again more than PROGRAM_REALERT_SECONDS after the last one (so one launch is one alert)."""
        program = (program or "").lower()
        if program not in self._programs:
            return []
        local = self._local(when)
        self._roll_day(local)
        last = self._programs_alerted.get(program)
        if last is not None and (when - last).total_seconds() < PROGRAM_REALERT_SECONDS:
            return []
        self._programs_alerted[program] = when
        return [(
            RULE_POLICY,
            f"Acceptable-use policy violation: {self._programs_label} {program} started on this device. {ACTION_PROGRAM}",
        )]

    # -- reporting -----------------------------------------------------------
    def usage_summary(self, now: datetime | None = None) -> dict:
        """Today's minutes per category, sent with the heartbeat and shown on the dashboard."""
        local = self._local(now or datetime.now().astimezone())
        self._roll_day(local)
        cats = {}
        for key, cat in self.policy.get("categories", {}).items():
            cats[key] = {
                "label": cat.get("label", key),
                "minutes": len(self._minutes.get(key, ())),
                "limit": int(cat.get("limit_minutes", 0)),
            }
        return {"date": self._date, "in_work_hours": self.in_work_hours(local), "categories": cats}
