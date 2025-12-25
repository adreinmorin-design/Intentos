import os
import json
import tempfile
from gui_intentos.gui_intentos import IntentOSPaths, append_log, append_sharing_event


def test_append_log_and_sharing_event_creates_files_and_content():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # append log
        append_log(paths, "test message")
        assert os.path.exists(paths.log_file)
        with open(paths.log_file, "r", encoding="utf-8") as f:
            content = f.read()
        assert "test message" in content

        # append sharing event
        event = {"type": "test_event", "value": 123}
        append_sharing_event(paths, event)
        assert os.path.exists(paths.sharing_log_file)
        with open(paths.sharing_log_file, "r", encoding="utf-8") as f:
            line = f.readline().strip()
        data = json.loads(line)
        assert data["type"] == "test_event"
        assert "ts" in data
