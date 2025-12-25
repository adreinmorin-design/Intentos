"""Simple test runner for environments without pytest available."""
import importlib

MODULES = [
    "tests.test_logging_helpers",
    "tests.test_json_helpers",
    "tests.test_subsystem_helpers",
    "tests.test_subsystems_all",
    "tests.test_owner_permissions",
    "tests.test_permissions_consent",
    "tests.test_suggestions",
    "tests.test_backend_repair",
    "tests.test_undo",
    "tests.test_microphone_location_consent",
    "tests.test_telemetry",
    "tests.test_keyword_spotter",
]

failed = False
for m in MODULES:
    print(f"Running {m}")
    mod = importlib.import_module(m)
    for name in dir(mod):
        if name.startswith("test_"):
            print(f" - {name}()", end=" ... ")
            try:
                getattr(mod, name)()
                print("ok")
            except AssertionError as e:
                print("FAIL")
                print(e)
                failed = True
            except Exception as e:
                print("ERROR")
                print(e)
                failed = True

if failed:
    print("Some tests failed.")
    raise SystemExit(1)
else:
    print("All tests passed.")
