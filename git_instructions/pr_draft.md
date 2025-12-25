PR Title: Fix keyword spotter test to be runner-independent

Description:
This PR fixes `tests/test_keyword_spotter.py` to avoid relying on pytest's `tmp_path` fixture so the project's test runner can run it reliably. The change wraps the test in a `tempfile.TemporaryDirectory()` context manager.

Motivation:
- The project's test runner (used by `python -m tests.run_all`) doesn't provide the pytest fixtures, which caused the test suite to fail in CI/local runs where pytest fixtures aren't available.

Testing:
- Ran full test suite locally (via `python -m tests.run_all`) and confirmed all tests pass.

Suggested reviewers: @your-team
Labels: tests, bug
