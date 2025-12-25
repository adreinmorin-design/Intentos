import tempfile
import os

from gui_intentos.gui_intentos import ensure_vosk_model, IntentOSPaths


def test_ensure_vosk_model_missing_returns_false():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # No model present and no auto_download -> False
        assert ensure_vosk_model(paths, auto_download=False) is False


def test_ensure_vosk_model_auto_download_bad_url_returns_false():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # Provide an invalid URL to simulate failed download
        assert ensure_vosk_model(paths, auto_download=True, url="http://invalid.local/model.zip") is False

# Note: Full download-and-extract tests would require network access and a small test artifact; for
# unit-test safety we keep this conservative and deterministic.
