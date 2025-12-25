import os
import json
import tempfile
from gui_intentos.gui_intentos import IntentOSPaths, OwnerInfo, save_owner, load_owner, verify_owner_passphrase, get_owner_role, set_owner_permissions


def test_owner_passphrase_and_permissions_persistence():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        owner = OwnerInfo(name="Alice", passphrase="s3cr3t", role="owner", permissions={"can_restart": True})
        save_owner(paths, owner)

        # load and verify
        loaded = load_owner(paths)
        assert loaded is not None
        assert loaded.name == "Alice"
        assert loaded.permissions.get("can_restart") is True

        # verify passphrase
        assert verify_owner_passphrase(paths, "s3cr3t") is True
        assert verify_owner_passphrase(paths, "wrong") is False

        # get role
        assert get_owner_role(paths, "s3cr3t") == "owner"
        assert get_owner_role(paths, "wrong") is None

        # update permissions
        set_owner_permissions(paths, loaded, {"can_restart": False, "new_perm": 1})
        loaded2 = load_owner(paths)
        assert loaded2.permissions.get("can_restart") is False
        assert loaded2.permissions.get("new_perm") == 1
