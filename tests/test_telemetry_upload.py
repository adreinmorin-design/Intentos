import tempfile
import json
import io
from urllib.error import URLError
from gui_intentos.gui_intentos import IntentOSPaths, _safe_write_json, save_owner
import gui_intentos.telemetry_upload as tu


class FakeResp(io.StringIO):
    def __init__(self, body, status=200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_upload_refuses_without_telemetry_consent():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # ensure telemetry consent not given
        perms = _safe_write_json(paths.permissions_file, {"features": {"telemetry": {"consent_given": False}}})
        ok, report = tu.upload_all_queued(paths, "http://example.invalid/upload", "pass", dry_run=True)
        assert ok is False
        assert "consent" in report.lower()


def test_upload_requires_owner_passphrase():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # give telemetry consent
        _safe_write_json(paths.permissions_file, {"features": {"telemetry": {"consent_given": True}}})
        # set owner
        owner = {"name": "o", "passphrase": "secret"}
        _safe_write_json(paths.owner_file, owner)
        # add small telemetry
        with open(os.path.join(paths.config_dir, "telemetry.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": "t1", "event": "e1"}) + "\n")
        ok, report = tu.upload_all_queued(paths, "http://example.invalid/upload", "wrongpass", dry_run=True)
        assert ok is False
        assert "owner" in report.lower()


import os

def test_upload_succeeds_and_clears_events(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # give telemetry consent and owner
        _safe_write_json(paths.permissions_file, {"features": {"telemetry": {"consent_given": True}}})
        _safe_write_json(paths.owner_file, {"name": "o", "passphrase": "secret"})
        # add 3 events
        with open(os.path.join(paths.config_dir, "telemetry.jsonl"), "w", encoding="utf-8") as f:
            for i in range(3):
                f.write(json.dumps({"ts": f"t{i}", "event": f"e{i}"}) + "\n")

        def fake_urlopen(req, timeout=1):
            return FakeResp("ok", status=200)

        monkeypatch.setattr("gui_intentos.telemetry_upload.urlopen", fake_urlopen)
        ok, report = tu.upload_all_queued(paths, "http://example.invalid/upload", "secret", batch_size=2)
        assert ok is True
        # telemetry file should be gone or empty
        remaining = tu._read_local_telemetry(paths)
        assert remaining == []


def test_partial_failure_preserves_events(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        _safe_write_json(paths.permissions_file, {"features": {"telemetry": {"consent_given": True}}})
        _safe_write_json(paths.owner_file, {"name": "o", "passphrase": "secret"})
        # add 3 events
        with open(os.path.join(paths.config_dir, "telemetry.jsonl"), "w", encoding="utf-8") as f:
            for i in range(3):
                f.write(json.dumps({"ts": f"t{i}", "event": f"e{i}"}) + "\n")

        calls = {"n": 0}

        def fake_urlopen(req, timeout=1):
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeResp("ok", status=200)
            raise URLError("network")

        monkeypatch.setattr("gui_intentos.telemetry_upload.urlopen", fake_urlopen)
        ok, report = tu.upload_all_queued(paths, "http://example.invalid/upload", "secret", batch_size=2)
        # first batch uploaded, second failed; should not be considered fully ok
        assert ok is False
        remaining = tu._read_local_telemetry(paths)
        # should contain the remaining event(s)
        assert len(remaining) >= 1
