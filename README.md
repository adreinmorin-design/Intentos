# Intentos
An Intent based bot that learns from the data gathered from users to create custom tailored experiences with the bot being able to understand different types of slangs based off different examples of intents

---

## Recent refactor & perf notes
We've recently consolidated several duplicated helpers and added safe, centralized utilities for logging and JSON persistence. See `docs/refactor_and_performance.md` for details and actionable suggestions (background logging, JSON caching, health monitor improvements).

All changes were implemented conservatively with tests; run `python -m tests.run_all` to validate locally.

CI: A GitHub Actions workflow was added at `.github/workflows/python-tests.yml` to run the tests on push and pull requests.
