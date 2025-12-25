import os
import io
import json
import tempfile
import gui_intentos.gui_intentos as gi
from gui_intentos.gui_intentos import (
    IntentOSPaths,
    load_permissions,
    set_feature_consent,
    get_feature_consent,
    load_listening_state,
    save_listening_state,
    get_location,
    load_cached_location,
    MicrophoneListener,
)


def test_permissions_include_microphone_and_location():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(str(td))
        perms = load_permissions(paths)
        assert "microphone" in perms.get("features", {})
        assert "location" in perms.get("features", {})


def test_microphone_consent_enables_listening():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(str(td))
        # Ensure default listening state is disabled
        s = load_listening_state(paths)
        s.enabled = False
        save_listening_state(paths, s)

        # grant microphone consent
        ok = set_feature_consent(paths, "microphone", True)
        assert ok
        assert get_feature_consent(paths, "microphone") is True

        s2 = load_listening_state(paths)
        assert s2.enabled is True

        # revoke consent
        ok = set_feature_consent(paths, "microphone", False)
        assert ok
        assert get_feature_consent(paths, "microphone") is False
        s3 = load_listening_state(paths)
        assert s3.enabled is False


def test_get_location_requires_consent_and_fetches():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(str(td))
        # Ensure no consent
        set_feature_consent(paths, "location", False)
        loc = get_location(paths)
        assert loc is None

        # Now mock urlopen to return fake JSON
        fake = {"city": "Testville", "region": "Testland"}
        class FakeResp(io.StringIO):
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False
        def fake_urlopen(url, timeout=1):
            return FakeResp(json.dumps(fake))

        old = gi.urlopen
        try:
            gi.urlopen = fake_urlopen
            # grant consent and fetch
            ok = set_feature_consent(paths, "location", True)
            assert ok
            loc = get_location(paths)
            assert isinstance(loc, dict)
            assert loc.get("city") == "Testville"

            # cached location should be readable
            cached = load_cached_location(paths)
            assert cached and cached.get("region") == "Testland"
        finally:
            gi.urlopen = old


def test_microphone_listener_not_crash_when_dependency_missing():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(str(td))
        ml = MicrophoneListener(paths)
        # When dependency missing, must be marked unavailable and start/stop must be safe
        assert hasattr(ml, "available")
        if not ml.available:
            assert ml.start() is False
            # stop may return True or False but must not raise
            ml.stop()
        else:
            # If available in environment, try start/stop safely
            ok = ml.start()
            assert isinstance(ok, bool)
            # stopping should not raise
            ok2 = ml.stop()
            assert isinstance(ok2, bool)
