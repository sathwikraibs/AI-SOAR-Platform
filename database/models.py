from sqlalchemy import Column, Integer, String, DateTime, Boolean
from database.database import Base


class DetectionRuleState(Base):
    """
    Persisted enable/disable state for a detection rule (see
    backend/main.py's RULE_DEFINITIONS for the canonical list of rule
    keys). One row per rule, created lazily the first time a rule is
    toggled -- a rule with no row yet is treated as enabled (the
    default). detection-agent polls GET /detection-rules to read this
    (see detection-agent/rule_state.py).
    """
    __tablename__ = "detection_rule_state"

    rule_key = Column(String, primary_key=True)
    enabled = Column(Boolean, nullable=False, default=True)


class SshSession(Base):
    """
    One row per POST /ssh/connect attempt made from the dashboard's
    SSH / Sessions tab -- so the session-log table there shows what
    actually happened instead of hardcoded demo rows.
    """
    __tablename__ = "ssh_sessions"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False, default=22)
    username = Column(String, nullable=False)
    success = Column(Boolean, nullable=False)
    output = Column(String, nullable=True)   # combined diagnostic output on success
    error = Column(String, nullable=True)    # failure reason on failure


class AuditLog(Base):
    """
    A real, append-only log of things that actually happened -- alert
    ingestion, analyst approve/reject decisions -- for the dashboard's
    Audit tab and Response Center's "recent actions" feed. Both read from
    this same table (Response Center just filters to approve/reject rows)
    rather than maintaining two parallel logs.
    """
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False)
    actor = Column(String, nullable=False)     # "system" (ingestion) | "analyst" (approve/reject)
    action = Column(String, nullable=False)    # e.g. "Alert ingested", "Approved response", "Rejected response"
    target = Column(String, nullable=False)    # e.g. "ALT-42"
    source_ip = Column(String, nullable=True)
    result = Column(String, nullable=False, default="Success")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False, default="Open")
    ip = Column(String, nullable=True)
    hash = Column(String, nullable=True)
    timestamp = Column(DateTime, nullable=False)

    # Which detection-agent rule produced this alert (e.g.
    # "login_brute_force", "path_traversal") -- null for alerts submitted
    # by hand rather than by the watcher. Powers the Detection Rules tab's
    # real per-rule trigger counts.
    rule_key = Column(String, nullable=True)

    # Which device the alert is about, when it came from an endpoint agent
    # (e.g. the Sysmon agent sends its machine name). Null for alerts that
    # aren't tied to one of our devices. For these alerts `ip` is the
    # *remote* address involved (e.g. where a process connected to), not
    # the device's own address.
    host = Column(String, nullable=True)

    # Day 3 (Nanda) -- threat-intelligence enrichment
    ip_reputation = Column(String, nullable=True)      # "Clean" | "Suspicious" | "Malicious" | "Unknown"
    hash_reputation = Column(String, nullable=True)     # "Clean" | "Suspicious" | "Malicious" | "Unknown"
    threat_score = Column(Integer, nullable=True)       # 0-100, higher = worse
    mitre_technique = Column(String, nullable=True)     # e.g. "T1110 - Brute Force"

    # Day 3 (Nanda) -- automated response engine
    risk_score = Column(Integer, nullable=True)          # 0-100 composite score (60% severity / 40% threat_score)
    response_action = Column(String, nullable=True)       # playbook name, e.g. "Credential / Brute-Force Response"
    response_playbook = Column(String, nullable=True)     # JSON-encoded list of {"action": str, "auto": bool} steps
    response_status = Column(String, nullable=True)       # "auto_resolved" | "pending_approval" | "approved_and_executed" | "rejected"


class AdminAccount(Base):
    """
    An admin/analyst identity for the dashboard's Admin Panel tab. This is
    NOT a real security boundary -- nothing else in this backend checks a
    password or a session token before doing anything (see ssh_manager.py's
    docstring for the same point about /ssh/connect). It exists so actions
    can be attributed to a real person ("who was on shift when this
    happened") rather than everything just saying "analyst". Password is
    stored salted+hashed (see backend/main.py's _hash_password), which is
    good hygiene but doesn't change the fact that no endpoint actually
    enforces being logged in as anyone.
    """
    __tablename__ = "admin_accounts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    company_id = Column(String, nullable=False)
    role = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    password_salt = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)


class AdminSession(Base):
    """
    One row per admin login (creating a new admin logs them in too), closed
    out with logout_at when they log out -- backs the Admin Panel's "who
    accessed when" log. admin_name/company_id/role are a snapshot at login
    time (not a live join to AdminAccount) so this history still reads
    correctly even if that admin's profile is later changed.
    """
    __tablename__ = "admin_sessions"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, nullable=False)
    admin_name = Column(String, nullable=False)
    company_id = Column(String, nullable=False)
    role = Column(String, nullable=True)
    login_at = Column(DateTime, nullable=False)
    logout_at = Column(DateTime, nullable=True)


class ApprovalPolicy(Base):
    """
    Persisted auto-approve/manual policy per severity level or per
    playbook, set from the Admin Panel tab. policy_key is "severity:<name>"
    or "playbook:<key>". NOTE (deliberate, current scope): this is a
    recorded policy, not yet read by the response engine -- POST
    /alerts doesn't check it, so it does not yet change what actually
    happens to a real incoming alert. That's a follow-up, not an oversight;
    see the Admin Panel tab's own note about this.
    """
    __tablename__ = "approval_policy"

    policy_key = Column(String, primary_key=True)
    mode = Column(String, nullable=False, default="manual")  # "auto" | "manual"
    updated_at = Column(DateTime, nullable=False)
    updated_by = Column(String, nullable=True)


class ManagedAsset(Base):
    """
    A manually-registered device/employee asset -- the actual LAN
    inventory, as opposed to the Assets tab's other rows, which are just
    inferred from whichever Alert.source values happen to have triggered
    an alert. This is what backs the "Add Asset" form: a real record that
    exists whether or not that device has ever fired an alert yet, ahead
    of the LAN-monitoring review milestone.
    """
    __tablename__ = "managed_assets"

    id = Column(Integer, primary_key=True, index=True)
    employee_name = Column(String, nullable=False)
    hostname = Column(String, nullable=False)
    lan_ip = Column(String, nullable=False)      # auto-detected at submit time (see backend/main.py's /assets/detect)
    mac_address = Column(String, nullable=True)  # auto-detected via ARP lookup; not always resolvable
    ssh_enabled = Column(Boolean, nullable=False, default=False)
    department = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False)


class EndpointAgent(Base):
    """
    One row per device running the Sysmon endpoint agent (endpoint-agent/).
    The agent registers itself and refreshes last_seen with a heartbeat every
    ~10 seconds, so "online" is a real liveness signal: a device is online if
    its last heartbeat was recent. Backs the connected-devices panel on the
    dashboard's Assets tab.
    """
    __tablename__ = "endpoint_agents"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, nullable=False, unique=True, index=True)
    ip = Column(String, nullable=True)
    os = Column(String, nullable=True)
    agent_version = Column(String, nullable=True)
    sysmon_status = Column(String, nullable=True)   # "running" | "not detected" | "simulated"
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    events_total = Column(Integer, nullable=False, default=0)
    # Whose device this is (set with --owner when the agent starts).
    owner = Column(String, nullable=True)
    # Per-device monitoring switch, controlled from the dashboard's Assets tab.
    # While False the backend ignores this device's events and alerts, and the
    # agent stops reading Sysmon (it keeps sending heartbeats so it still shows
    # as connected). Defaults to on.
    monitoring_enabled = Column(Boolean, nullable=False, default=True)
    # Today's time per activity category as last reported by the agent's
    # heartbeat (JSON text), e.g. {"date": "...", "categories": {...}}.
    usage_json = Column(String, nullable=True)


class EndpointEvent(Base):
    """
    One row per Sysmon event an agent reported (process started, network
    connection, file created, ...), newest kept, oldest pruned. This is the
    per-device activity feed; only the suspicious ones also become alerts
    (flagged=True marks those).
    """
    __tablename__ = "endpoint_events"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False)
    event_id = Column(Integer, nullable=True)       # Sysmon event ID, e.g. 1 = process created
    event_type = Column(String, nullable=False)     # "Process", "Network", "File", "Registry", ...
    summary = Column(String, nullable=False)
    flagged = Column(Boolean, nullable=False, default=False)


class AppSetting(Base):
    """
    Small key/value store for switches that are controlled from the dashboard,
    for example "vpn_auto_block" and "monitoring_global" (see backend/main.py).
    A missing key means "use the default", so existing databases need nothing.
    """
    __tablename__ = "app_settings"

    key = Column(String, primary_key=True)
    value = Column(String, nullable=False)
    updated_at = Column(DateTime, nullable=False)
