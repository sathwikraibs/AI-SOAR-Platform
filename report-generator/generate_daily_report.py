"""
Autonomous 24-hour digest report generator.

This is deliberately a *separate* process from generate_report.py, not a
mode flag on it: generate_report.py writes a new PDF every ~20 seconds for
whatever alerts are new since its last cycle (an incremental feed), while
this writes exactly ONE consolidated PDF every 24 hours covering every
alert timestamped within that trailing 24-hour window (a daily digest) --
different cadence, different alert selection, different filename prefix,
different reports/ subfolder, so they can't be confused with each other or
overwrite one another's files.

Steps, once per DAILY_INTERVAL_SECONDS (default 24h):
  1. Pull the full alert list from the existing GET /alerts endpoint
     (same real backend endpoint generate_report.py already uses).
  2. Keep only alerts whose timestamp falls in the last WINDOW_HOURS hours.
  3. Build one PDF from that set -- reusing generate_report.py's build_pdf
     so the layout (severity/status breakdown, MITRE techniques, response
     actions) stays identical, just retitled as a 24-hour summary instead
     of a per-cycle delta.
  4. Save it into reports/daily/ as daily_report_<timestamp>.pdf.

Unlike generate_report.py (which skips writing when there's nothing new),
this always writes a report each cycle, even with zero alerts in the
window -- it's a scheduled daily digest, not an incremental change feed,
so "nothing happened today" is itself a real, worth-recording report.

The two matching endpoints that make these downloadable from the
dashboard's 24-Hour Report tab -- GET /reports/daily (list) and
GET /reports/daily/{filename} (download) -- live in backend/main.py right
next to the existing GET /reports pair.

Run: python3 report-generator/generate_daily_report.py
(backend must already be running at API_URL; see generate_report.py)
"""

import os
import sys
import time
from datetime import datetime, timedelta, timezone

# Both generator scripts live in this same report-generator/ folder, and
# running this file directly (not as a package) already puts that folder
# first on sys.path -- this insert just makes that explicit rather than
# relying on Python's default script-directory behavior.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_report import build_pdf, fetch_alerts  # noqa: E402

DAILY_INTERVAL_SECONDS = 24 * 60 * 60  # 24 hours
WINDOW_HOURS = 24
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports", "daily")

os.makedirs(REPORTS_DIR, exist_ok=True)


def _parse_alert_time(raw: str | None) -> datetime | None:
    """
    Alert timestamps come back from the backend as naive strings that are
    actually UTC with no "Z"/offset attached (the same root cause as the
    dashboard's toLocalTime() fix in page.tsx) -- parse and explicitly
    label them UTC so the 24h-window comparison below is correct rather
    than silently comparing against the wrong clock.
    """
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", ""))
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def run_cycle() -> str:
    all_alerts = fetch_alerts()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=WINDOW_HOURS)

    window_alerts = []
    for a in all_alerts:
        ts = _parse_alert_time(a.get("timestamp"))
        # An alert with an unparsable/missing timestamp is kept rather than
        # silently dropped -- excluding it would understate the digest.
        if ts is None or ts >= cutoff:
            window_alerts.append(a)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"daily_report_{timestamp}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    build_pdf(
        window_alerts,
        filepath,
        title="AI-SOAR 24-Hour Summary Report",
        subtitle=f"Covers {len(window_alerts)} alert(s) from the last {WINDOW_HOURS} hours.",
        empty_message=f"No alerts in the last {WINDOW_HOURS} hours.",
    )
    print(f"[daily-report-generator] Wrote {filename} ({len(window_alerts)} alert(s) in the last {WINDOW_HOURS}h)")
    return filename


def main():
    print(f"[daily-report-generator] Writing a 24-hour digest PDF every {DAILY_INTERVAL_SECONDS}s to {REPORTS_DIR}")
    try:
        while True:
            run_cycle()
            time.sleep(DAILY_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[daily-report-generator] Stopped.")


if __name__ == "__main__":
    main()
