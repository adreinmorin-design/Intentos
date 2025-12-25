import tempfile
import json
from gui_intentos.gui_intentos import (
    IntentOSPaths,
    create_suggestion,
    list_suggestions,
    check_intents_and_create_suggestions,
    approve_suggestion,
    set_suggestion_state,
    _load_suggestions,
    save_owner,
    OwnerInfo,
)


def test_check_intents_and_approval_executes():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        # create root/data/intents.json
        d = {
            "intents": []
        }
        intents_dir = paths.repo_root + "\\\\root\\\\data"
        # ensure dir
        import os
        os.makedirs(os.path.join(paths.repo_root, "root", "data"), exist_ok=True)
        intents_file = os.path.join(paths.repo_root, "root", "data", "intents.json")
        intents = [
            {"name": "greet", "examples": ["hi"]},
        ]
        with open(intents_file, "w", encoding="utf-8") as f:
            json.dump(intents, f, ensure_ascii=False, indent=2)

        created = check_intents_and_create_suggestions(paths, min_examples=3, add_examples_count=2)
        assert len(created) >= 1

        # find suggestion id for greet
        sgs = list_suggestions(paths)
        sg = next((s for s in sgs if s.get("payload", {}).get("intent_name") == "greet"), None)
        assert sg is not None
        sid = sg.get("id")

        # approve and execute
        ok = approve_suggestion(paths, sid, operator="tester")
        assert ok is True

        # verify intents file now has additional examples
        with open(intents_file, "r", encoding="utf-8") as f:
            intents2 = json.load(f)
        g = next((it for it in intents2 if it.get("name") == "greet"), None)
        assert g is not None
        assert len(g.get("examples", [])) >= 2


def test_owner_protected_suggestion_requires_owner_passphrase():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        sid = create_suggestion(paths, "add_examples", "Owner required test", {"intent_name": "x", "examples": ["a"]}, owner_required=True)
        # attempt to approve without owner should fail
        res = approve_suggestion(paths, sid, operator="tester")
        assert res is False
        # create owner and try with passphrase
        owner = OwnerInfo(name="Alice", passphrase="secret")
        save_owner(paths, owner)
        res2 = approve_suggestion(paths, sid, operator="tester", owner_passphrase="secret")
        assert res2 is True


def test_reject_suggestion_marks_rejected():
    with tempfile.TemporaryDirectory() as td:
        paths = IntentOSPaths(td)
        sid = create_suggestion(paths, "add_examples", "Reject me", {"intent_name": "y", "examples": ["a"]})
        set_suggestion_state(paths, sid, "rejected", operator="tester")
        s = next((x for x in _load_suggestions(paths) if x.get("id") == sid), None)
        assert s is not None
        assert s.get("state") == "rejected"
