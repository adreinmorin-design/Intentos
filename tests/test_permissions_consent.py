import tempfile
from gui_intentos.gui_intentos import (
    IntentOSPaths,
    load_permissions,
    save_permissions,
    get_feature_consent,
    set_feature_consent,
    can_use_feature,
    save_owner,
    OwnerInfo,
)


def test_consent_flow_basic():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        perms = load_permissions(paths)

        # cloud_intents requires consent and defaults to False
        assert get_feature_consent(paths, "cloud_intents") is False

        # grant consent (no owner required)
        assert set_feature_consent(paths, "cloud_intents", True) is True
        assert get_feature_consent(paths, "cloud_intents") is True

        # feature must also be enabled to be usable
        perms = load_permissions(paths)
        perms["features"]["cloud_intents"]["enabled"] = True
        save_permissions(paths, perms)
        assert can_use_feature(paths, "cloud_intents") is True


def test_owner_protected_consent_requires_passphrase():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # remote_logging is owner_protected by default
        perms = load_permissions(paths)
        assert perms["features"]["remote_logging"]["owner_required"] is True

        # without an owner, attempting to grant consent fails
        assert set_feature_consent(paths, "remote_logging", True) is False

        # create an owner and try again with correct passphrase
        owner = OwnerInfo(name="Alice", passphrase="s3cr3t")
        save_owner(paths, owner)
        assert set_feature_consent(paths, "remote_logging", True, owner_passphrase="s3cr3t") is True
        assert get_feature_consent(paths, "remote_logging") is True

