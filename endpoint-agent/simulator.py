"""
Simulated Sysmon events, for demonstrating the endpoint agent on a machine
that has no Sysmon (or isn't Windows), and for showing several "devices" from
one laptop: run the agent once per fake host name.

The events have exactly the same shape as real ones read from the Windows
event log (see sysmon_events.py), so they go through the same detection
rules and the same pipeline. Nothing here touches the real machine; they are
just dictionaries. The scenarios mirror real attacker behaviour:

  powershell    encoded, hidden PowerShell started from Explorer
  office        Word spawning cmd.exe
  mimikatz      a Mimikatz command line
  lsass         an unknown program opening LSASS memory
  persistence   a Run key pointing at a Public-folder program, and a script dropped in Startup
  ransomware    shadow-copy deletion, then a burst of .locked files
  tor           a connection to an address on the anonymizer blocklist (demo range)
  scripthost    mshta.exe talking to an external address
  youtube       35 minutes of YouTube lookups (over the streaming limit; backdated so it is instant)
  social        32 minutes of Instagram lookups (over the social-media limit)
  malicioussite a lookup of a known-malicious (test) domain
  vpnclient     ProtonVPN being started on the device
  all           every scenario above, one after another
"""

import itertools
import random
from datetime import datetime, timedelta, timezone

_record_ids = itertools.count(1)

SCENARIOS = ["powershell", "office", "mimikatz", "lsass", "persistence", "ransomware", "tor", "scripthost",
             "youtube", "social", "malicioussite", "vpnclient"]


def make_event(event_id: int, when=None, **data) -> dict:
    return {
        "event_id": event_id,
        "record_id": next(_record_ids),
        "time": when or datetime.now(timezone.utc),
        "computer": "SIMULATED",
        "data": data,
    }


def _process(image, parent, cmd):
    return make_event(
        1,
        Image=image,
        CommandLine=cmd,
        ParentImage=parent,
        ParentCommandLine=parent,
        User="LAB\\student",
        IntegrityLevel="Medium",
        OriginalFileName=image.rsplit("\\", 1)[-1],
    )


def _connect(image, ip, port=443):
    return make_event(3, Image=image, Protocol="tcp", Initiated="true", SourceIp="192.168.1.20",
                      DestinationIp=ip, DestinationPort=str(port), User="LAB\\student")


# Everyday activity so the feed looks like a real machine.
_BENIGN = [
    lambda: _process("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Windows\\explorer.exe", "chrome.exe --profile-directory=Default"),
    lambda: _process("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\services.exe", "svchost.exe -k netsvcs -p"),
    lambda: _process("C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\explorer.exe", "notepad.exe notes.txt"),
    lambda: _process("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\explorer.exe", "cmd.exe"),
    lambda: _process("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "C:\\Windows\\explorer.exe", "WINWORD.EXE report.docx"),
    lambda: _connect("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "142.250.77.110"),
    lambda: _connect("C:\\Windows\\System32\\svchost.exe", "20.190.159.4"),
    lambda: _connect("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "151.101.1.69"),
    lambda: make_event(11, Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                       TargetFilename="C:\\Users\\student\\Downloads\\lecture-notes.pdf"),
    lambda: make_event(22, Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", QueryName="www.wikipedia.org"),
]


def benign_events(n: int = 2) -> list[dict]:
    return [random.choice(_BENIGN)() for _ in range(n)]


def scenario_events(name: str) -> list[list[dict]]:
    """
    A scenario as a list of steps; each step is a list of events delivered
    together, so multi-step attacks (a burst of encrypted files) can arrive
    over several polls.
    """
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    if name == "powershell":
        return [[_process(ps, "C:\\Windows\\explorer.exe",
                          "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")]]
    if name == "office":
        return [[_process("C:\\Windows\\System32\\cmd.exe",
                          "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                          "cmd.exe /c whoami && net user")]]
    if name == "mimikatz":
        return [[_process("C:\\Users\\Public\\mimikatz.exe", "C:\\Windows\\System32\\cmd.exe",
                          "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit")]]
    if name == "lsass":
        return [[make_event(10, SourceImage="C:\\Users\\Public\\dumper.exe", TargetImage="C:\\Windows\\System32\\lsass.exe",
                            GrantedAccess="0x1010", SourceProcessId="4412", TargetProcessId="712")]]
    if name == "persistence":
        return [
            [make_event(13, EventType="SetValue", Image="C:\\Windows\\System32\\reg.exe",
                        TargetObject="HKU\\S-1-5-21-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                        Details="C:\\Users\\Public\\updater.exe")],
            [make_event(11, Image=ps,
                        TargetFilename="C:\\Users\\student\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\sync.bat")],
        ]
    if name == "ransomware":
        steps = [[_process("C:\\Windows\\System32\\vssadmin.exe", "C:\\Windows\\System32\\cmd.exe",
                           "vssadmin.exe delete shadows /all /quiet")]]
        files = [make_event(11, Image="C:\\Users\\student\\AppData\\Local\\Temp\\svc_update.exe",
                            TargetFilename=f"C:\\Users\\student\\Documents\\{n}.locked")
                 for n in ("thesis.docx", "budget.xlsx", "photos.zip", "project.pptx", "notes.txt", "report.pdf", "data.csv")]
        steps += [files[:4], files[4:]]
        return steps
    if name in ("youtube", "social"):
        domains = (["www.youtube.com", "rr3---sn-ab5l6n7y.googlevideo.com", "i.ytimg.com"] if name == "youtube"
                   else ["www.instagram.com", "scontent.cdninstagram.com"])
        minutes = 35 if name == "youtube" else 32
        browser = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
        start = datetime.now(timezone.utc) - timedelta(minutes=minutes - 1)
        events = [make_event(22, when=start + timedelta(minutes=i), Image=browser, QueryName=domains[i % len(domains)])
                  for i in range(minutes)]
        return [events[:20], events[20:]]
    if name == "malicioussite":
        return [[make_event(22, Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", QueryName="malware.wicar.org")]]
    if name == "vpnclient":
        return [[_process("C:\\Program Files\\Proton\\VPN\\ProtonVPN.exe", "C:\\Windows\\explorer.exe", "ProtonVPN.exe")]]
    if name == "tor":
        return [[_connect("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "203.0.113.9")]]
    if name == "scripthost":
        return [[_connect("C:\\Windows\\System32\\mshta.exe", "93.184.216.34", 80)]]
    raise ValueError(f"unknown scenario '{name}' (choose from: {', '.join(SCENARIOS)}, all)")


def expand_attack_arg(arg: str) -> list[str]:
    """'all' or 'tor,lsass' -> list of scenario names (validated)."""
    names = SCENARIOS if arg.strip().lower() == "all" else [a.strip().lower() for a in arg.split(",") if a.strip()]
    for n in names:
        if n not in SCENARIOS:
            raise ValueError(f"unknown scenario '{n}' (choose from: {', '.join(SCENARIOS)}, all)")
    return names
