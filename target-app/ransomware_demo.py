"""
Demo-only ransomware simulation for the target app's own file store.

Used by the token-protected /internal/demo/ransomware endpoint in app.py so a
ransomware attack can be demonstrated against a target app that is hosted
online (for example on PythonAnywhere), where the detection-agent cannot touch
the files directly. It behaves like ransomware would -- "encrypts" files,
renames them to *.locked, drops a ransom note -- but:

  * only on a small set of demo SCADA files this module creates itself,
  * only inside the app's uploads folder,
  * fully reversible (restore), and removable (cleanup).

It never touches any other file, never spreads and never contacts anything.
The "encryption" is a throwaway XOR keystream seeded per file; the seeds live
in a small state file next to the uploads folder, which is what makes restore
possible.

The endpoint is disabled unless the environment variable
ENABLE_DEMO_ENDPOINTS=1 is set on the server, so a deployed copy cannot be
triggered by accident.
"""

import json
import os
import random

NOTE_NAME = "README_DECRYPT.txt"
LOCK_EXT = ".locked"

NOTE_TEXT = """\
[SIMULATION - this is a training exercise for the AI-SOAR demo. Nothing real was
 encrypted and no payment is needed. The wallet below is not real.]

YOUR FILES HAVE BEEN ENCRYPTED

All substation configuration, breaker settings and historian data on this server
have been encrypted. To decrypt your files you must pay 2.5 BTC to:

    bc1q-DEMO-NOT-A-REAL-WALLET

Do not try to recover the files yourself. You have 72 hours before the price doubles.
"""


def demo_files() -> dict[str, str]:
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


def _xor(data: bytes, seed: int) -> bytes:
    stream = random.Random(seed).randbytes(len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


class Demo:
    def __init__(self, uploads_dir: str, state_path: str):
        self.dir = os.path.abspath(uploads_dir)
        self.state_path = state_path

    # -- helpers ---------------------------------------------------------
    def _inside(self, path: str) -> bool:
        real = os.path.realpath(path)
        return real.startswith(os.path.realpath(self.dir) + os.sep)

    def _load(self) -> dict:
        try:
            with open(self.state_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save(self, state: dict) -> None:
        with open(self.state_path, "w") as f:
            json.dump(state, f)

    # -- steps -----------------------------------------------------------
    def prepare(self) -> dict:
        """Creates the demo files (readable) so there is something to encrypt."""
        state = self._load()
        if any(i.get("encrypted") for i in state.values()):
            return {"ok": False, "message": "The demo files are already encrypted. Run restore first."}
        os.makedirs(self.dir, exist_ok=True)
        new_state, skipped = {}, []
        for name, content in demo_files().items():
            path = os.path.join(self.dir, name)
            if os.path.exists(path) and name not in state:
                skipped.append(name)          # a real file with that name: never touched
                continue
            if not os.path.exists(path):
                with open(path, "w", newline="\n") as f:
                    f.write(content)
            new_state[name] = {"seed": random.SystemRandom().randrange(2**32), "encrypted": False}
        self._save(new_state)
        return {"ok": True, "message": f"Prepared {len(new_state)} demo files", "files": list(new_state), "skipped": skipped}

    def encrypt_next(self) -> dict:
        """Encrypts one more demo file. 'remaining' tells the caller when to stop."""
        state = self._load()
        for name, info in state.items():
            if info.get("encrypted"):
                continue
            path = os.path.join(self.dir, name)
            if not os.path.isfile(path) or not self._inside(path):
                info["encrypted"] = True       # nothing to encrypt; don't loop on it
                continue
            with open(path, "rb") as f:
                data = f.read()
            with open(path, "wb") as f:
                f.write(_xor(data, info["seed"]))
            os.rename(path, path + LOCK_EXT)
            info["encrypted"] = True
            self._save(state)
            remaining = sum(1 for i in state.values() if not i.get("encrypted"))
            return {"ok": True, "encrypted": name, "remaining": remaining}
        self._save(state)
        return {"ok": True, "encrypted": None, "remaining": 0}

    def drop_note(self) -> dict:
        with open(os.path.join(self.dir, NOTE_NAME), "w") as f:
            f.write(NOTE_TEXT)
        return {"ok": True, "message": f"Dropped ransom note {NOTE_NAME}"}

    def restore(self) -> dict:
        state = self._load()
        restored = []
        for name, info in state.items():
            locked = os.path.join(self.dir, name + LOCK_EXT)
            plain = os.path.join(self.dir, name)
            if info.get("encrypted") and os.path.isfile(locked) and self._inside(locked):
                with open(locked, "rb") as f:
                    data = f.read()
                with open(plain, "wb") as f:
                    f.write(_xor(data, info["seed"]))
                os.remove(locked)
                info["encrypted"] = False
                restored.append(name)
        note = os.path.join(self.dir, NOTE_NAME)
        if os.path.isfile(note):
            os.remove(note)
        self._save(state)
        return {"ok": True, "message": f"Restored {len(restored)} files and removed the ransom note", "restored": restored}

    def cleanup(self) -> dict:
        self.restore()
        state = self._load()
        deleted = []
        for name in state:
            plain = os.path.join(self.dir, name)
            if os.path.isfile(plain) and self._inside(plain):
                os.remove(plain)
                deleted.append(name)
        try:
            os.remove(self.state_path)
        except OSError:
            pass
        return {"ok": True, "message": f"Deleted {len(deleted)} demo files", "deleted": deleted}

    def status(self) -> dict:
        state = self._load()
        return {"ok": True, "files": {n: ("ENCRYPTED" if i.get("encrypted") else "clean") for n, i in state.items()}}
