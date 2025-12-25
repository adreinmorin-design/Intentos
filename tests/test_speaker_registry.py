import tempfile
import os
from gui_intentos.speaker_registry import SpeakerRegistry


def test_enroll_and_identify_fallback():
    with tempfile.TemporaryDirectory() as td:
        from gui_intentos.gui_intentos import IntentOSPaths
        paths = IntentOSPaths(td)
        sr = SpeakerRegistry(paths)
        # Without resemblyzer this uses fingerprint fallback
        audio1 = b"dummy-audio-bytes-1"
        audio2 = b"different-audio-bytes-2"
        assert sr.enroll("alice", audio1) is True
        assert sr.identify(audio1) == "alice"
        assert sr.identify(audio2) is None


def test_remove_and_list():
    with tempfile.TemporaryDirectory() as td:
        from gui_intentos.gui_intentos import IntentOSPaths
        paths = IntentOSPaths(td)
        sr = SpeakerRegistry(paths)
        sr.enroll("bob", b"bobbytes")
        assert "bob" in sr.list_speakers()
        assert sr.remove("bob") is True
        assert "bob" not in sr.list_speakers()
