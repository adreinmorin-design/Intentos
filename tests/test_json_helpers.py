import os
import tempfile
from gui_intentos.gui_intentos import IntentOSPaths, load_listening_state, ListeningState


def test_load_listening_state_creates_default_and_handles_invalid():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # ensure missing file -> default
        if os.path.exists(paths.listening_file):
            os.remove(paths.listening_file)
        state = load_listening_state(paths)
        assert isinstance(state, ListeningState)
        assert state.consent_given is False
        assert state.enabled is False
        assert os.path.exists(paths.listening_file)

        # write invalid content and ensure it resets
        with open(paths.listening_file, "w", encoding="utf-8") as f:
            f.write("not a json")
        state2 = load_listening_state(paths)
        assert isinstance(state2, ListeningState)
        assert state2.consent_given is False
        assert state2.enabled is False
