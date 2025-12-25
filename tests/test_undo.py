import os
import time
import json
import subprocess
import sys
import tempfile
from gui_intentos.gui_intentos import IntentOSPaths, list_undo_entries, perform_undo_action


def test_undo_kill_process():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # Ensure misc dir exists
        os.makedirs(os.path.join(td, "misc"), exist_ok=True)
        # Start a long-running subprocess
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform.startswith("win") else 0
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], creationflags=creationflags)
        pid = proc.pid
        try:
            # write undo entry
            entry = {"action": "kill", "pid": pid, "ts": "test", "sid": "undo-test-1"}
            p = os.path.join(td, "misc", "undo.log")
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

            entries = list_undo_entries(paths)
            assert any(e.get("pid") == pid for e in entries)

            print("PID to kill:", pid)
            print("Performing undo...")
            ok, msg = perform_undo_action(paths, entry)
            print("perform_undo_action returned:", ok, msg)
            assert ok, f"perform_undo_action failed: {msg}"

            # Wait for process to exit
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                assert False, "Process still running after undo"
        finally:
            try:
                proc.kill()
            except Exception:
                pass