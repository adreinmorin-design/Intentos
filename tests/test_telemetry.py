import tempfile
import os
import json
from gui_intentos.gui_intentos import IntentOSPaths, record_telemetry_event, load_telemetry_events, set_feature_consent


def test_telemetry_writes_when_consent_granted():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # ensure telemetry disabled
        set_feature_consent(paths, "telemetry", False)
        ok = record_telemetry_event(paths, {"ts":"t","event":"x"})
        assert ok is False

        # enable telemetry
        ok = set_feature_consent(paths, "telemetry", True)
        assert ok is True

        # record event
        e_ok = record_telemetry_event(paths, {"ts":"t2","event":"y"})
        assert e_ok is True
        evs = load_telemetry_events(paths)
        assert any(e.get("event") == "y" for e in evs)
