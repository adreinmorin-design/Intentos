# Refactor & Performance Notes

## Summary of changes (conservative, behavior-preserving)
- Consolidated logging functions in `gui_intentos/gui_intentos.py`:
  - Added `_append_line()` and kept `append_log`, `append_audit`, `append_sharing_event` public APIs unchanged.
- Added `_load_json_with_default()` to centralize safe read/write of JSON files and self-healing behavior.
  - Migrated `load_listening_state`, `load_maintenance_state`, and `load_permissions` as examples.
- Added `Subsystem.ensure_file()` and `Subsystem.check_file()` to `intentos_wizard_automation.py` and migrated `BackendSubsystem` as proof-of-concept.
- Added tests for logging helpers, JSON helpers, and subsystem helpers under `tests/` and a tiny test runner `tests/run_all.py`.

## Why these changes
- Reduce duplicated code to make future maintenance easier.
- Centralize error handling and logging behavior so fixes/changes are applied once.
- Keep original public APIs and self-healing semantics to minimize risk.

## Performance improvement suggestions (safe, incremental)
Below are concise, non-invasive changes that can improve performance and responsiveness, with short implementation notes.

### 1) Asynchronous / batch logging
Problem: Frequent per-call file opens/writes can be expensive on heavy activity.
Suggestion: Add an optional background logger using a Queue and a single writer thread. Keep current `append_log()` as a thin wrapper that enqueues messages—fallback to synchronous write if threading is disabled or fails.

Minimal sketch:
```python
from queue import Queue, Empty
import threading, time

_log_queue = Queue()
_log_worker = None

def _log_worker_fn():
    while True:
        try:
            path, line = _log_queue.get(timeout=0.5)
        except Empty:
            continue
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            # fallback to stderr
            print(f"[IntentOS LOG FAIL] {line}", file=sys.stderr)

def start_background_logging():
    global _log_worker
    if _log_worker is None:
        _log_worker = threading.Thread(target=_log_worker_fn, daemon=True)
        _log_worker.start()

def append_log(...):
    _log_queue.put((paths.log_file, f"[{_ts()}] {message}\n"))
```
Benefit: reduces system call overhead on frequent logs, and is safe—loss only on process crash without flush.

### 2) Cache small config reads in memory
Problem: Multiple UI methods may call `load_permissions()` or similar repeatedly.
Suggestion: Load once into an `app`-level cache (already present as `self.permissions` in `IntentOSGUI`) and ensure `save_*` functions update the cached value. Avoid reading disk on every UI tick.

### 3) BackendHealthMonitor: use Event instead of sleep and reduce blocking
Problem: `time.sleep()` and blocking `urlopen()` in a thread can cause delayed shutdown.
Suggestion: Use a cancel Event and shorter blocking with `timeout`, or make this monitor use an async library or requests with timeouts and better exception handling. Also make the polling interval adaptive (exponential backoff on repeated failures).

### 4) GUI redraw optimizations
Problem: Frequent redrawing can be expensive in Tk; `_redraw_all()` should only update changed widgets.
Suggestion: Track last-state (health status, maintenance countdown, theme) and only call `configure()` or canvas redraw when values change. Also debounce redraws using `after()` with small delays.

### 5) Subprocess use: avoid capture_output on long outputs
Problem: Capturing large subprocess outputs can fill memory.
Suggestion: Use streaming (read from stdout iteratively) or set a safe buffer and/or write to temporary file if output is large.

## Tests & safety
- Unit tests were added for the new helpers; changes keep existing behavior.
- For any further perf changes (e.g., background logging), add tests that ensure graceful fallback when threading is unavailable and that on normal operation messages are persisted.

## Next steps
- (Optional) Implement background logging (low risk) and add tests for flush behavior.
- Migrate other subsystems to `Subsystem.ensure_file()` to further reduce duplication.
- Added a GitHub Actions workflow: `.github/workflows/python-tests.yml` that runs `python -m tests.run_all` on push and pull_request.

---
_If you want, I can implement the background logger now and add tests; it’s a small, safe improvement that yields real runtime benefits._
