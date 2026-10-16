"""
Safe ransomware simulator for demonstrating the SOAR's ransomware detection.

It behaves like ransomware would on the target app's file store -- encrypts
files, renames them to *.locked and drops a ransom note -- but only on a
small set of demo SCADA files that it creates itself, and everything is
reversible. It never touches any other file, never leaves the folder, never
spreads and never contacts anything.

    python3 detection-agent/simulate_ransomware.py attack    # create demo files, then "encrypt" them
    python3 detection-agent/simulate_ransomware.py restore   # decrypt, rename back, remove the note
    python3 detection-agent/simulate_ransomware.py cleanup   # restore, then delete the demo files
    python3 detection-agent/simulate_ransomware.py status    # what state the demo files are in

Start detection-agent/watcher.py first (it needs to be running to see the
attack happen). The encryption is a throwaway XOR keystream seeded per file;
the seeds are kept in .ransomware_sim_state.json next to this script, which
is what makes 'restore' possible.

Environment: SOAR_RANSOMWARE_WATCH_DIR overrides the folder (used for testing).
"""

import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WATCH_DIR = os.path.abspath(os.environ.get("SOAR_RANSOMWARE_WATCH_DIR") or os.path.join(HERE, "..", "target-app", "uploads"))
STATE_FILE = os.path.join(HERE, ".ransomware_sim_state.json")
NOTE_NAME = "README_DECRYPT.txt"
LOCK_EXT = ".locked"
DELAY_BETWEEN_FILES = 0.4   # seconds -- looks like a progressive attack in the live feed

NOTE_TEXT = """\
[SIMULATION - this is a training exercise for the AI-SOAR demo. Nothing real was
 encrypted and no payment is needed. The wallet below is not real.]

YOUR FILES HAVE BEEN ENCRYPTED

All substation configuration, breaker settings and historian data on this server
have been encrypted. To decrypt your files you must pay 2.5 BTC to:

    bc1q-DEMO-NOT-A-REAL-WALLET

Do not try to recover the files yourself. You have 72 hours before the price doubles.
"""


def _demo_files() -> dict[str, str]:
    """name -> readable content, like the data a grid operator would keep."""
    rows = "\n".join(f"{i},Substation-{i % 9 + 1},{(i * 37) % 500 + 100},{(i * 13) % 60 + 20},NORMAL" for i in range(1, 60))
    breakers = "\n".join(f"BRK-{i:03d},trip_threshold={(i * 7) % 90 + 400}A,reclose_delay={(i % 5) + 1}s,status=ARMED" for i in range(1, 50))
    forecast = json.dumps(
        {"region": "North Grid", "year": 2026, "hourly_load_mw": [(h * 17) % 300 + 800 for h in range(96)], "notes": "peak expected 18:00-20:00"},
        indent=2,
    )
    plc = "\n".join(f"PLC-{i:02d} firmware 4.{i % 7}.{i % 3} checksum ok, last patched 2026-0{i % 9 + 1}-1{i % 9}" for i in range(1, 40))
    topology = "<grid>\n" + "\n".join(f'  <link from="SS-{i}" to="SS-{i + 1}" capacity_mw="{200 + i * 10}"/>' for i in range(1, 45)) + "\n</grid>\n"
    historian = "timestamp,sensor,value\n" + "\n".join(f"2026-03-14T{h:02d}:{m:02d}:00Z,SENSOR-{h % 6},{(h * 60 + m) % 97 + 3}" for h in range(0, 24) for m in (0, 30))
    return {
        "substation_alpha7_loads.csv": "id,site,load_mw,temp_c,state\n" + rows + "\n",
        "breaker_settings_delta3.csv": "breaker,settings,reclose,status\n" + breakers + "\n",
        "load_forecast_2026.json": forecast + "\n",
        "plc_firmware_inventory.txt": plc + "\n",
        "grid_topology.xml": topology,
        "scada_historian_export.csv": historian + "\n",
    }


def _keystream(seed: int, length: int) -> bytes:
    return random.Random(seed).randbytes(length)


def _xor(data: bytes, seed: int) -> bytes:
    return bytes(a ^ b for a, b in zip(data, _keystream(seed, len(data))))


def _inside_watch_dir(path: str) -> bool:
    real = os.path.realpath(path)
    root = os.path.realpath(WATCH_DIR)
    return real.startswith(root + os.sep)


def _load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def _save_state(state: dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def attack() -> int:
    state = _load_state()
    if any(info.get("encrypted") for info in state.values()):
        print("The demo files are already encrypted. Run 'restore' first.")
        return 1

    os.makedirs(WATCH_DIR, exist_ok=True)
    print(f"Target folder: {WATCH_DIR}")
    print("Preparing demo SCADA files...")
    new_state = {}
    for name, content in _demo_files().items():
        path = os.path.join(WATCH_DIR, name)
        if os.path.exists(path) and name not in state:
            print(f"  skipping {name}: a file with that name already exists and isn't ours (not touching it)")
            continue
        if not os.path.exists(path):
            with open(path, "w", newline="\n") as f:
                f.write(content)
        new_state[name] = {"seed": random.SystemRandom().randrange(2**32), "encrypted": False}
    state = new_state
    _save_state(state)

    print("Waiting 6s so the watcher records the normal state first...")
    time.sleep(6)

    print("Encrypting...")
    for name, info in state.items():
        path = os.path.join(WATCH_DIR, name)
        if not _inside_watch_dir(path) or not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(_xor(data, info["seed"]))
        os.rename(path, path + LOCK_EXT)          # report.csv -> report.csv.locked
        info["encrypted"] = True
        _save_state(state)
        print(f"  encrypted {name} -> {name}{LOCK_EXT}")
        time.sleep(DELAY_BETWEEN_FILES)

    with open(os.path.join(WATCH_DIR, NOTE_NAME), "w") as f:
        f.write(NOTE_TEXT)
    print(f"Dropped ransom note {NOTE_NAME}")
    print("Done. The SOAR should raise a Critical ransomware alert within a few seconds.")
    print("To undo: python3 detection-agent/simulate_ransomware.py restore")
    return 0


def restore() -> int:
    """Decrypts the demo files, renames them back and removes the ransom note."""
    state = _load_state()
    if not state:
        print("Nothing to restore (no simulation state found).")
        return 0
    for name, info in state.items():
        locked = os.path.join(WATCH_DIR, name + LOCK_EXT)
        plain = os.path.join(WATCH_DIR, name)
        if info.get("encrypted") and os.path.isfile(locked) and _inside_watch_dir(locked):
            with open(locked, "rb") as f:
                data = f.read()
            with open(plain, "wb") as f:
                f.write(_xor(data, info["seed"]))
            os.remove(locked)
            info["encrypted"] = False
            print(f"  restored {name}")
    note = os.path.join(WATCH_DIR, NOTE_NAME)
    if os.path.isfile(note):
        os.remove(note)
        print(f"  removed {NOTE_NAME}")
    _save_state(state)
    print("Restored. The demo files are readable again; run 'attack' to repeat, or 'cleanup' to delete them.")
    return 0


def cleanup() -> int:
    """Restores anything still encrypted, then deletes the demo files so the folder is as it was before."""
    restore()
    state = _load_state()
    for name in state:
        plain = os.path.join(WATCH_DIR, name)
        if os.path.isfile(plain) and _inside_watch_dir(plain):
            os.remove(plain)
            print(f"  deleted demo file {name}")
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    print("Clean.")
    return 0


def status() -> int:
    state = _load_state()
    if not state:
        print("No simulation in progress.")
        return 0
    for name, info in state.items():
        print(f"  {name}: {'ENCRYPTED' if info.get('encrypted') else 'clean'}")
    return 0


if __name__ == "__main__":
    commands = {"attack": attack, "restore": restore, "cleanup": cleanup, "status": status}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print(__doc__)
        sys.exit(2)
    sys.exit(commands[sys.argv[1]]())
