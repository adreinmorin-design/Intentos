#!/usr/bin/env python
"""
IntentOS Advanced Owner Console
Resilient, self-healing, Owner-grade GUI with:

- Owner registration and lock.
- Theme switching with orb avatar.
- Backend health monitor.
- Always listening control (with consent).
- 1-hour timed maintenance mode with countdown and auto-refresh.
- Engine & Services control with progress bars.
- Diagnostics with progress bar.
- Subsystem manager.
- Config editor.
- Intent runner.
- Logs viewer.
- Data sharing inspector (sharing.log).
- Permissions matrix (permissions.json).
- Plugin manager (plugin manifests).
- Audit timeline (audit.log).
- Autonomous recovery of missing directories/configs with human direction.
"""

import os
import sys
import json
import time
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import hmac
from dataclasses import dataclass, asdict, field
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List, Callable
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime, timedelta


# ============================================================================
# PATHS & CONFIG MODELS
# ============================================================================

@dataclass
class OwnerInfo:
    name: str
    passphrase: str
    role: str = "owner"
    permissions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ListeningState:
    consent_given: bool
    enabled: bool


@dataclass
class MaintenanceState:
    enabled: bool
    started_at: Optional[str]  # ISO UTC string
    duration_seconds: int      # default 3600 (1 hour)


class IntentOSPaths:
    """
    Central path registry. Ensures directory structure exists.
    Self-healing: auto-creates missing core directories.
    """
    def __init__(self, repo_root: str) -> None:
        self.repo_root = os.path.abspath(repo_root)

        self.config_dir = os.path.join(self.repo_root, "config")
        self.misc_dir = os.path.join(self.repo_root, "misc")
        self.plugins_dir = os.path.join(self.repo_root, "plugins")
        self.backend_dir = os.path.join(self.repo_root, "backend")
        self.dashboard_dir = os.path.join(self.repo_root, "dashboard")
        self.cli_dir = os.path.join(self.repo_root, "cli")

        self._ensure_directories()

        self.owner_file = os.path.join(self.config_dir, "owner.json")
        self.listening_file = os.path.join(self.config_dir, "listening.json")
        self.maintenance_file = os.path.join(self.config_dir, "maintenance.json")
        self.permissions_file = os.path.join(self.config_dir, "permissions.json")
        self.suggestions_file = os.path.join(self.config_dir, "suggestions.json")
        self.backend_pid_file = os.path.join(self.config_dir, "backend.pid")
        self.backend_log_file = os.path.join(self.misc_dir, "backend.log")

        self.log_file = os.path.join(self.misc_dir, "intentos.log")
        self.sharing_log_file = os.path.join(self.misc_dir, "sharing.log")
        self.audit_log_file = os.path.join(self.misc_dir, "audit.log")

        self.backend_main = os.path.join(self.backend_dir, "main.py")
        self.dashboard_index = os.path.join(self.dashboard_dir, "index.html")
        self.cli_script = os.path.join(self.cli_dir, "cli.py")
        self.root_file = os.path.join(self.repo_root, "root")

    def _ensure_directories(self) -> None:
        """
        Self-healing directory creation. Never raises, always logs on failure.
        """
        for d in [
            self.config_dir,
            self.misc_dir,
            self.plugins_dir,
            self.backend_dir,
            self.dashboard_dir,
            self.cli_dir,
        ]:
            try:
                os.makedirs(d, exist_ok=True)
            except Exception as e:
                # Logging may not yet be wired; best effort to print.
                print(f"[IntentOS] Failed to create directory {d}: {e}", file=sys.stderr)


# ============================================================================
# LOGGING SYSTEMS (RESILIENT)
# ============================================================================

def _ts() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _append_line(path: str, line: str) -> None:
    """Low-level append helper. Keeps stderr fallback behavior consistent."""
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        print(f"[IntentOS LOG FAIL] {line}", file=sys.stderr)


def append_log(paths: IntentOSPaths, message: str) -> None:
    """Best-effort logging; never raises."""
    line = f"[{_ts()}] {message}\n"
    _append_line(paths.log_file, line)


def append_audit(paths: IntentOSPaths, message: str) -> None:
    """Best-effort audit logging; never raises."""
    line = f"[{_ts()}] {message}\n"
    _append_line(paths.audit_log_file, line)


def append_sharing_event(paths: IntentOSPaths, event: Dict[str, Any]) -> None:
    """Best-effort sharing event logging; never raises."""
    event = dict(event)
    event["ts"] = _ts()
    try:
        _append_line(paths.sharing_log_file, json.dumps(event) + "\n")
    except Exception as e:
        append_log(paths, f"Failed to write sharing event: {e}")


# ============================================================================
# PERSISTENCE HELPERS (SELF-HEALING)
# ============================================================================

def _safe_read_json(path: str) -> Optional[Dict[str, Any]]:
    """
    Safely read JSON from a file. Returns None on any error.
    """
    try:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _safe_write_json(path: str, data: Dict[str, Any]) -> None:
    """
    Safely write JSON to a file. Logs errors; never raises.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[IntentOS] Failed to write JSON {path}: {e}", file=sys.stderr)


def _load_json_with_default(paths: IntentOSPaths, path: str, default: Dict[str, Any], validator: Optional[Callable[[Any], bool]] = None, reset_log_message: Optional[str] = None) -> Dict[str, Any]:
    """Load JSON returning a dict; if missing or invalid, write and return default. Uses append_log for reset messages."""
    data = _safe_read_json(path)
    if data is None:
        _safe_write_json(path, default)
        return default
    if validator and not validator(data):
        if reset_log_message:
            append_log(paths, reset_log_message)
        _safe_write_json(path, default)
        return default
    if not isinstance(data, dict):
        if reset_log_message:
            append_log(paths, reset_log_message)
        _safe_write_json(path, default)
        return default
    return data


def load_owner(paths: IntentOSPaths) -> Optional[OwnerInfo]:
    data = _safe_read_json(paths.owner_file)
    if not data:
        return None
    try:
        return OwnerInfo(
            name=str(data.get("name", "")).strip(),
            passphrase=str(data.get("passphrase", "")),
            role=str(data.get("role", "owner")),
            permissions=data.get("permissions", {}) or {},
        )
    except Exception as e:
        append_log(paths, f"Invalid owner.json structure: {e}")
        return None


def save_owner(paths: IntentOSPaths, owner: OwnerInfo) -> None:
    try:
        _safe_write_json(paths.owner_file, asdict(owner))
    except Exception as e:
        append_log(paths, f"Failed to save owner: {e}")


def verify_owner_passphrase(paths: IntentOSPaths, passphrase: str) -> bool:
    """Returns True if provided passphrase matches stored owner passphrase."""
    owner = load_owner(paths)
    if not owner:
        return False
    try:
        return hmac.compare_digest(str(owner.passphrase), str(passphrase))
    except Exception:
        return False


def get_owner_role(paths: IntentOSPaths, passphrase: str) -> Optional[str]:
    """Return the owner's role only if passphrase matches; otherwise None."""
    if not verify_owner_passphrase(paths, passphrase):
        return None
    owner = load_owner(paths)
    return owner.role if owner else None


def set_owner_permissions(paths: IntentOSPaths, owner: OwnerInfo, permissions: Dict[str, Any]) -> None:
    """Update owner permissions in-memory and persist to disk."""
    try:
        owner.permissions = dict(permissions)
        save_owner(paths, owner)
        append_log(paths, "Owner permissions updated.")
    except Exception as e:
        append_log(paths, f"Failed to update owner permissions: {e}")


def load_listening_state(paths: IntentOSPaths) -> ListeningState:
    data = _load_json_with_default(
        paths,
        paths.listening_file,
        {"consent_given": False, "enabled": False},
        validator=lambda d: isinstance(d, dict),
        reset_log_message="Invalid listening.json structure, resetting.",
    )
    try:
        return ListeningState(
            consent_given=bool(data.get("consent_given", False)),
            enabled=bool(data.get("enabled", False)),
        )
    except Exception as e:
        append_log(paths, f"Invalid listening.json structure, resetting: {e}")
        state = ListeningState(consent_given=False, enabled=False)
        save_listening_state(paths, state)
        return state


def save_listening_state(paths: IntentOSPaths, state: ListeningState) -> None:
    try:
        _safe_write_json(paths.listening_file, asdict(state))
    except Exception as e:
        append_log(paths, f"Failed to save listening state: {e}")


def load_maintenance_state(paths: IntentOSPaths) -> MaintenanceState:
    data = _load_json_with_default(
        paths,
        paths.maintenance_file,
        {"enabled": False, "started_at": None, "duration_seconds": 3600},
        validator=lambda d: isinstance(d, dict),
        reset_log_message="Invalid maintenance.json structure, resetting.",
    )
    try:
        return MaintenanceState(
            enabled=bool(data.get("enabled", False)),
            started_at=data.get("started_at"),
            duration_seconds=int(data.get("duration_seconds", 3600)),
        )
    except Exception as e:
        append_log(paths, f"Invalid maintenance.json structure, resetting: {e}")
        state = MaintenanceState(enabled=False, started_at=None, duration_seconds=3600)
        save_maintenance_state(paths, state)
        return state


def save_maintenance_state(paths: IntentOSPaths, state: MaintenanceState) -> None:
    try:
        _safe_write_json(paths.maintenance_file, asdict(state))
    except Exception as e:
        append_log(paths, f"Failed to save maintenance state: {e}")


def load_permissions(paths: IntentOSPaths) -> Dict[str, Any]:
    default = {
        "features": {
            "cloud_intents": {
                "description": "Send intents to cloud backends.",
                "requires_consent": True,
                "consent_key": "cloud_intents_enabled",
                "owner_required": False,
                "default": False,
                "enabled": False,
                "consent_given": False,
            },
            "remote_logging": {
                "description": "Send logs to a remote server.",
                "requires_consent": True,
                "consent_key": "remote_logging_enabled",
                "owner_required": True,
                "default": False,
                "enabled": False,
                "consent_given": False,
            },
            "microphone": {
                "description": "Allow microphone capture for intent recognition (if consented the microphone will be listening by default).",
                "requires_consent": True,
                "consent_key": "microphone_enabled",
                "owner_required": False,
                "default": False,
                "enabled": False,
                "consent_given": False,
            },
            "location": {
                "description": "Share approximate location to improve location-based intents.",
                "requires_consent": True,
                "consent_key": "location_enabled",
                "owner_required": False,
                "default": False,
                "enabled": False,
                "consent_given": False,
            },
            "telemetry": {
                "description": "Allow aggregated, anonymized in-product telemetry to help improve IntentOS (local only until enabled for optional upload).",
                "requires_consent": True,
                "consent_key": "telemetry_enabled",
                "owner_required": False,
                "default": False,
                "enabled": False,
                "consent_given": False,
            },
        }
    }
    data = _load_json_with_default(
        paths,
        paths.permissions_file,
        default,
        validator=lambda d: isinstance(d, dict),
        reset_log_message="permissions.json not a dict, resetting.",
    )
    if "features" not in data or not isinstance(data["features"], dict):
        data["features"] = {}
    return data


def save_permissions(paths: IntentOSPaths, data: Dict[str, Any]) -> None:
    try:
        # Normalize missing consent flags for older files
        features = data.get("features", {})
        for k, v in features.items():
            if "consent_given" not in v:
                v["consent_given"] = False
            if "owner_required" not in v:
                v["owner_required"] = False
        _safe_write_json(paths.permissions_file, data)
    except Exception as e:
        append_log(paths, f"Failed to save permissions: {e}")


def get_feature_info(paths: IntentOSPaths, key: str) -> Optional[Dict[str, Any]]:
    data = _safe_read_json(paths.permissions_file)
    if not data or "features" not in data:
        return None
    return data["features"].get(key)


def get_feature_consent(paths: IntentOSPaths, key: str) -> bool:
    info = get_feature_info(paths, key)
    if not info:
        return False
    return bool(info.get("consent_given", False))


def set_feature_consent(paths: IntentOSPaths, key: str, value: bool, owner_passphrase: Optional[str] = None) -> bool:
    # Ensure permissions file is loaded/initialized
    data = _safe_read_json(paths.permissions_file)
    if not data:
        data = load_permissions(paths)
    features = data.setdefault("features", {})
    feature = features.get(key)
    if not feature:
        return False
    # if owner required, validate
    if feature.get("owner_required"):
        if owner_passphrase is None or not verify_owner_passphrase(paths, owner_passphrase):
            return False
    feature["consent_given"] = bool(value)
    try:
        save_permissions(paths, data)
    except Exception as e:
        append_log(paths, f"Failed to persist consent changes for {key}: {e}")
        return False

    # Special behavior: if microphone consent changes, auto-enable/disable listening
    try:
        if key == "microphone":
            state = load_listening_state(paths)
            state.enabled = bool(value)
            save_listening_state(paths, state)
            append_log(paths, f"Listening enabled set to {state.enabled} due to microphone consent change")
    except Exception as e:
        append_log(paths, f"Failed to update listening state after microphone consent change: {e}")

    append_log(paths, f"Consent for {key} set to {value}")
    return True


def can_use_feature(paths: IntentOSPaths, key: str) -> bool:
    """Returns True if feature exists, enabled, and consent (when required) has been granted."""
    info = get_feature_info(paths, key)
    if not info:
        return False
    if not bool(info.get("enabled", False)):
        return False
    if info.get("requires_consent"):
        return bool(info.get("consent_given", False))
    return True


# ============================================================================
# SUGGESTIONS (AI recommendations, operator approval required)
# ============================================================================

import uuid


def _load_suggestions(paths: IntentOSPaths) -> list:
    try:
        data = _safe_read_json(paths.suggestions_file)
        if not isinstance(data, list):
            append_log(paths, "suggestions.json malformed, resetting to empty list")
            data = []
            _safe_write_json(paths.suggestions_file, data)
        return data
    except Exception as e:
        append_log(paths, f"Failed loading suggestions: {e}")
        return []


def _save_suggestions(paths: IntentOSPaths, suggestions: list) -> None:
    try:
        _safe_write_json(paths.suggestions_file, suggestions)
    except Exception as e:
        append_log(paths, f"Failed saving suggestions: {e}")


def create_suggestion(paths: IntentOSPaths, kind: str, message: str, payload: dict, owner_required: bool = False) -> str:
    """Create a pending suggestion and persist it. Returns suggestion id."""
    suggestions = _load_suggestions(paths)
    # avoid duplicate pending suggestions for same kind + payload
    for s in suggestions:
        if s.get("state") == "pending" and s.get("kind") == kind and s.get("payload") == payload:
            return s.get("id")

    sid = uuid.uuid4().hex
    entry = {
        "id": sid,
        "ts": _ts(),
        "kind": kind,
        "message": message,
        "payload": payload,
        "owner_required": bool(owner_required),
        "state": "pending",
        "operator": None,
        "executed_at": None,
    }
    suggestions.append(entry)
    _save_suggestions(paths, suggestions)
    append_log(paths, f"Suggestion created: {kind} ({sid})")
    return sid


def list_suggestions(paths: IntentOSPaths, state: Optional[str] = None) -> list:
    all_s = _load_suggestions(paths)
    if state:
        return [s for s in all_s if s.get("state") == state]
    return all_s


def set_suggestion_state(paths: IntentOSPaths, sid: str, state: str, operator: Optional[str] = None) -> bool:
    suggestions = _load_suggestions(paths)
    for s in suggestions:
        if s.get("id") == sid:
            s["state"] = state
            s["operator"] = operator
            if state == "executed":
                s["executed_at"] = _ts()
            _save_suggestions(paths, suggestions)
            append_audit(paths, f"Suggestion {sid} marked {state} by {operator}")
            return True
    return False


def execute_suggestion(paths: IntentOSPaths, sid: str) -> bool:
    """Execute the suggestion's action. Returns True on success."""
    suggestions = _load_suggestions(paths)
    for s in suggestions:
        if s.get("id") != sid:
            continue
        if s.get("state") != "approved":
            append_log(paths, f"Attempt to execute suggestion {sid} in state {s.get('state')}")
            return False
        kind = s.get("kind")
        payload = s.get("payload") or {}

        try:
            if kind == "add_examples":
                # payload: {"intent_name": str, "examples": [str]}
                intents_dir = os.path.join(paths.repo_root, "root", "data")
                intents_file = os.path.join(intents_dir, "intents.json")
                try:
                    os.makedirs(intents_dir, exist_ok=True)
                except Exception:
                    pass
                intents = []
                if os.path.exists(intents_file):
                    try:
                        intents = json.loads(open(intents_file, "r", encoding="utf-8").read())
                    except Exception:
                        intents = []
                name = payload.get("intent_name")
                extras = payload.get("examples", [])
                updated = False
                for intent in intents:
                    if intent.get("name") == name:
                        ex = intent.setdefault("examples", [])
                        for e in extras:
                            if e not in ex:
                                ex.append(e)
                                updated = True
                if updated:
                    with open(intents_file, "w", encoding="utf-8") as f:
                        f.write(json.dumps(intents, ensure_ascii=False, indent=2))
                    append_log(paths, f"Suggestion executed: added examples to {name}")
                    return set_suggestion_state(paths, sid, "executed")
                else:
                    append_log(paths, f"Suggestion executed: no changes needed for {name}")
                    return set_suggestion_state(paths, sid, "executed")

            # Add other suggestion kinds here
            if kind == "repair_backend":
                # payload can include optional fields; support dry_run, attempts, autonomous
                dry = bool(payload.get("dry_run", False))
                attempts = int(payload.get("attempts", 1)) if payload.get("attempts") is not None else 1
                autonomous = bool(payload.get("autonomous", False))
                final_ok = False
                final_report = ""
                for attempt in range(attempts):
                    ok, report = attempt_backend_restart(paths, timeout=10, dry_run=dry)
                    final_report = report
                    if ok:
                        final_ok = True
                        break
                    # brief backoff
                    time.sleep(0.5)

                if final_ok:
                    append_log(paths, f"Suggestion executed: repair_backend {sid} succeeded")
                    # record undo hint (kill pid) for safety
                    try:
                        if os.path.exists(paths.backend_pid_file):
                            with open(paths.backend_pid_file, "r", encoding="utf-8") as f:
                                pid = f.read().strip()
                            undo = {"action": "kill", "pid": pid, "ts": _ts(), "sid": sid}
                            try:
                                with open(os.path.join(paths.repo_root, "misc", "undo.log"), "a", encoding="utf-8") as uf:
                                    uf.write(json.dumps(undo, ensure_ascii=False) + "\n")
                            except Exception:
                                pass
                    except Exception:
                        pass

                    set_suggestion_state(paths, sid, "executed")
                    append_audit(paths, f"Suggestion {sid} executed: backend repaired")
                    return True
                else:
                    append_log(paths, f"Suggestion executed: repair_backend {sid} failed: {final_report}")
                    # attach report and plan to suggestion payload for operator review
                    try:
                        suggestions = _load_suggestions(paths)
                        for s2 in suggestions:
                            if s2.get("id") == sid:
                                s2.setdefault("payload", {})["report"] = final_report
                                s2.setdefault("payload", {})["plan"] = generate_repair_plan(paths, final_report, kind="backend")
                        _save_suggestions(paths, suggestions)
                    except Exception:
                        pass
                    return False

            append_log(paths, f"Unknown suggestion kind: {kind}")
            return False
        except Exception as e:
            append_log(paths, f"Failed executing suggestion {sid}: {e}")
            return False


def approve_suggestion(paths: IntentOSPaths, sid: str, operator: str, owner_passphrase: Optional[str] = None) -> bool:
    """Approve a suggestion and execute it. Returns True on success."""
    suggestions = _load_suggestions(paths)
    for s in suggestions:
        if s.get("id") != sid:
            continue
        if s.get("state") != "pending":
            append_log(paths, f"Cannot approve suggestion {sid} in state {s.get('state')}")
            return False
        if s.get("owner_required"):
            if owner_passphrase is None or not verify_owner_passphrase(paths, owner_passphrase):
                append_log(paths, f"Failed owner verification while approving {sid}")
                return False
        # mark approved and record operator
        set_suggestion_state(paths, sid, "approved", operator)
        # execute immediately
        ok = execute_suggestion(paths, sid)
        if ok:
            append_audit(paths, f"Suggestion {sid} approved and executed by {operator}")
            return True
        else:
            append_log(paths, f"Suggestion {sid} approved by {operator} but execution failed")
            return False


def check_intents_and_create_suggestions(paths: IntentOSPaths, min_examples: int = 3, add_examples_count: int = 3) -> list:
    """Scan local intents and create suggestions when intents have fewer than min_examples.
    Returns a list of created suggestion ids.
    """
    created = []
    intents_dir = os.path.join(paths.repo_root, "root", "data")
    intents_file = os.path.join(intents_dir, "intents.json")
    intents = []
    if os.path.exists(intents_file):
        try:
            intents = json.loads(open(intents_file, "r", encoding="utf-8").read())
        except Exception:
            intents = []

    for intent in intents:
        name = intent.get("name")
        exs = intent.get("examples", []) or []
        if len(exs) < min_examples:
            needed = min_examples - len(exs)
            # prepare some generic examples as suggestions
            new_examples = [f"Example suggestion: add more examples for {name} ({i+1})" for i in range(add_examples_count)]
            msg = f"Intent '{name}' has {len(exs)} examples. Consider adding more examples to improve matching."
            sid = create_suggestion(paths, "add_examples", msg, {"intent_name": name, "examples": new_examples}, owner_required=False)
            created.append(sid)
    if created:
        append_log(paths, f"Created suggestions: {', '.join(created)}")
    return created


def attempt_backend_restart(paths: IntentOSPaths, timeout: int = 10, dry_run: bool = False) -> (bool, str):
    """Attempt to start the backend and wait until /health responds OK within timeout seconds.
    If dry_run is True, do not spawn a new process; only probe existing service.
    Returns (success: bool, report: str).
    """
    report_lines = []
    try:
        if not os.path.exists(paths.backend_main):
            msg = f"backend main not found at {paths.backend_main}"
            report_lines.append(msg)
            append_log(paths, msg)
            return False, "\n".join(report_lines)

        # Probe existing service if dry_run
        if dry_run:
            try:
                with urlopen("http://127.0.0.1:8000/health", timeout=2) as resp:
                    if resp.status == 200:
                        report_lines.append("Existing backend /health OK (dry_run).")
                        return True, "\n".join(report_lines)
                    else:
                        report_lines.append(f"Existing backend responded HTTP {resp.status} (dry_run)")
                        return False, "\n".join(report_lines)
            except Exception as e:
                report_lines.append(f"Existing backend not reachable (dry_run): {e}")
                return False, "\n".join(report_lines)

        # Ensure log dir exists
        try:
            os.makedirs(os.path.dirname(paths.backend_log_file), exist_ok=True)
        except Exception:
            pass

        # Start backend process, direct output to backend log
        try:
            lf = open(paths.backend_log_file, "a", encoding="utf-8")
        except Exception:
            lf = None

        try:
            proc = subprocess.Popen(
                [sys.executable, paths.backend_main],
                cwd=os.path.dirname(paths.backend_main),
                stdout=lf or subprocess.DEVNULL,
                stderr=lf or subprocess.DEVNULL,
            )
        except Exception as e:
            report_lines.append(f"Failed to spawn backend process: {e}")
            append_log(paths, report_lines[-1])
            if lf:
                try:
                    lf.close()
                except Exception:
                    pass
            return False, "\n".join(report_lines)

        # write pid file
        try:
            with open(paths.backend_pid_file, "w", encoding="utf-8") as f:
                f.write(str(proc.pid))
            report_lines.append(f"Spawned backend pid={proc.pid}")
        except Exception as e:
            report_lines.append(f"Could not write pid file: {e}")

        # Wait for health
        start = time.time()
        healthy = False
        last_err = None
        while time.time() - start < timeout:
            try:
                with urlopen("http://127.0.0.1:8000/health", timeout=2) as resp:
                    if resp.status == 200:
                        healthy = True
                        break
                    else:
                        last_err = f"HTTP {resp.status}"
            except Exception as e:
                last_err = str(e)
            time.sleep(0.5)

        if healthy:
            report_lines.append("Backend /health responded OK.")
            if lf:
                try:
                    lf.close()
                except Exception:
                    pass
            return True, "\n".join(report_lines)

        # Not healthy — collect tail of backend log
        report_lines.append(f"Backend did not become healthy within {timeout}s; last err: {last_err}")
        try:
            if os.path.exists(paths.backend_log_file):
                with open(paths.backend_log_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.read().splitlines()
                    tail = lines[-30:]
                    report_lines.append("--- backend.log tail ---")
                    report_lines.extend(tail)
        except Exception as e:
            report_lines.append(f"Failed to read backend log: {e}")

        if lf:
            try:
                lf.close()
            except Exception:
                pass

        return False, "\n".join(report_lines)
    except Exception as e:
        return False, f"Exception during restart attempt: {e}"


def generate_repair_plan(paths: IntentOSPaths, report: str, kind: str = "backend") -> list:
    """Generate a human-readable repair plan from a diagnostic report.
    Returns a list of steps (strings).
    """
    plan = []
    # Basic analysis of report keywords
    if not report:
        plan.append("No diagnostic report available. Inspect backend logs and retry health check.")
        return plan

    rl = report.lower()
    if "modulenotfounderror" in rl or "importerror" in rl:
        plan.append("Check Python dependencies and ensure required packages are installed.")
        plan.append("Run: python -m pip install -r requirements.txt in the backend directory.")
    if "permissionerror" in rl or "permission denied" in rl:
        plan.append("Check file permissions for backend files and logs. Run with appropriate user or adjust ACLs.")
    if "address already in use" in rl or ("errno" in rl and "address" in rl):
        plan.append("Port 8000 appears in use. Check for stray backend processes and free the port or configure a different port.")
        plan.append("Use: netstat/tcpview to find owner process or kill via PID.")
    if "traceback" in rl or "error" in rl:
        plan.append("Inspect the backend log tail included in the report for the traceback to find the failing module and line.")
    # Fallback steps
    plan.append("Step 1: Review the backend log tail included in the report.")
    plan.append("Step 2: If an ImportError is present, install missing dependencies, then re-run.")
    plan.append("Step 3: Attempt a graceful restart of the backend service and re-check /health.")
    plan.append("Step 4: If restart fails, consider reverting recent changes or restoring from backup.")
    plan.append("Step 5: If unsure, escalate to Owner and provide this diagnostics report.")
    return plan


def _undo_log_path(paths: IntentOSPaths) -> str:
    return os.path.join(paths.repo_root, "misc", "undo.log")


def list_undo_entries(paths: IntentOSPaths) -> list:
    entries = []
    p = _undo_log_path(paths)
    if not os.path.exists(p):
        return entries
    try:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        pass
    return entries


def perform_undo_action(paths: IntentOSPaths, entry: dict) -> (bool, str):
    """Perform an undo action described by an undo log entry.
    Returns (success, message).
    Supported actions: kill
    """
    action = entry.get("action")
    try:
        if action == "kill":
            pid = entry.get("pid")
            if pid is None:
                return False, "No pid in undo entry"
            try:
                pid_i = int(pid)
            except Exception:
                return False, f"Invalid pid: {pid}"
            # Check process exists
            try:
                os.kill(pid_i, 0)
            except Exception:
                return False, f"Process {pid_i} not running"
            try:
                try:
                    # Use os.kill where possible; on Windows this maps to TerminateProcess
                    import signal
                    try:
                        os.kill(pid_i, signal.SIGTERM)
                    except Exception:
                        # Fallback to SIGKILL equivalent
                        try:
                            os.kill(pid_i, 9)
                        except Exception:
                            pass
                except Exception:
                    pass
                append_audit(paths, f"Performed undo kill for pid {pid_i}")
                return True, f"Killed process {pid_i}"
            except Exception as e:
                return False, f"Failed to kill {pid_i}: {e}"

        return False, f"Unknown undo action: {action}"
    except Exception as e:
        return False, f"Exception during undo: {e}"

        # Start backend process, direct output to backend log
        try:
            lf = open(paths.backend_log_file, "a", encoding="utf-8")
        except Exception:
            lf = None

        try:
            proc = subprocess.Popen(
                [sys.executable, paths.backend_main],
                cwd=os.path.dirname(paths.backend_main),
                stdout=lf or subprocess.DEVNULL,
                stderr=lf or subprocess.DEVNULL,
            )
        except Exception as e:
            report_lines.append(f"Failed to spawn backend process: {e}")
            append_log(paths, report_lines[-1])
            if lf:
                try:
                    lf.close()
                except Exception:
                    pass
            return False, "\n".join(report_lines)

        # write pid file
        try:
            with open(paths.backend_pid_file, "w", encoding="utf-8") as f:
                f.write(str(proc.pid))
            report_lines.append(f"Spawned backend pid={proc.pid}")
        except Exception as e:
            report_lines.append(f"Could not write pid file: {e}")

        # Wait for health
        start = time.time()
        healthy = False
        last_err = None
        while time.time() - start < timeout:
            try:
                with urlopen("http://127.0.0.1:8000/health", timeout=2) as resp:
                    if resp.status == 200:
                        healthy = True
                        break
                    else:
                        last_err = f"HTTP {resp.status}"
            except Exception as e:
                last_err = str(e)
            time.sleep(0.5)

        if healthy:
            report_lines.append("Backend /health responded OK.")
            if lf:
                try:
                    lf.close()
                except Exception:
                    pass
            return True, "\n".join(report_lines)

        # Not healthy — collect tail of backend log
        report_lines.append(f"Backend did not become healthy within {timeout}s; last err: {last_err}")
        try:
            if os.path.exists(paths.backend_log_file):
                with open(paths.backend_log_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.read().splitlines()
                    tail = lines[-30:]
                    report_lines.append("--- backend.log tail ---")
                    report_lines.extend(tail)
        except Exception as e:
            report_lines.append(f"Failed to read backend log: {e}")

        if lf:
            try:
                lf.close()
            except Exception:
                pass

        return False, "\n".join(report_lines)
    except Exception as e:
        return False, f"Exception during restart attempt: {e}"


# ============================================================================
# DESKTOP NOTIFICATION (best-effort)
# ============================================================================

def send_desktop_notification(title: str, message: str) -> None:
    """Best-effort desktop notification.
    Tries `win10toast` if available; falls back to a PowerShell message box on Windows, otherwise logs.
    """
    try:
        try:
            from win10toast import ToastNotifier
            t = ToastNotifier()
            t.show_toast(title, message, duration=6)
            return
        except Exception:
            pass

        # Windows fallback: show a simple message box via PowerShell
        if sys.platform.startswith("win"):
            try:
                cmd = [
                    "powershell",
                    "-NoProfile",
                    "-WindowStyle", "Hidden",
                    "-Command",
                    f"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\"{message}\",\"{title}\")"
                ]
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except Exception:
                pass

        # Fallback: write to log (no desktop notifier available)
        append_log(IntentOSPaths(os.getcwd()), f"Notification: {title} - {message}")
    except Exception:
        pass


# ============================================================================
# SUBPROCESS WRAPPER (SAFE)
# ============================================================================


# ============================================================================
# MICROPHONE LISTENER (best-effort real capture when available)
# ============================================================================
class MicrophoneListener:
    """Best-effort microphone listener. Uses `sounddevice` when available.
    Safe fallbacks if dependency missing: the listener will be marked unavailable
    and calls to start/stop will be no-ops while still being safe and logged.
    """
    def __init__(self, paths: IntentOSPaths):
        self.paths = paths
        self.available = False
        self._running = False
        self._thread = None
        self._sd = None
        # lightweight counting for detected 'keyword' events (heuristic)
        self.keyword_counts = {}
        try:
            import sounddevice as sd  # optional dependency
            self._sd = sd
            self.available = True
        except Exception as e:
            append_log(paths, f"Microphone support not available (missing sounddevice): {e}")
            self.available = False

    def record_keyword_event(self, label: str = "keyword") -> None:
        """Record an anonymized local telemetry event (keyword detected)."""
        try:
            self.keyword_counts[label] = self.keyword_counts.get(label, 0) + 1
            # persist small local telemetry as json-lines only when telemetry consent given
            try:
                if get_feature_consent(self.paths, "telemetry"):
                    p = os.path.join(self.paths.config_dir, "telemetry.jsonl")
                    entry = {"ts": _ts(), "event": label}
                    with open(p, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except Exception as e:
                append_log(self.paths, f"Failed to record telemetry event: {e}")
        except Exception as e:
            append_log(self.paths, f"Error recording keyword event: {e}")

    def _rms(self, data) -> float:
        try:
            # data is usually a numpy array; compute RMS without requiring numpy import here
            flat = None
            try:
                flat = data.reshape(-1)
            except Exception:
                # fallback to list flatten
                flat = [v for row in data for v in row]
            s = 0.0
            n = 0
            for v in flat:
                try:
                    vv = float(v)
                except Exception:
                    continue
                s += vv * vv
                n += 1
            if n == 0:
                return 0.0
            return (s / n) ** 0.5
        except Exception as e:
            append_log(self.paths, f"Error computing RMS: {e}")
            return 0.0

    def _callback(self, indata, frames, time_info, status):
        try:
            if status:
                append_log(self.paths, f"Microphone stream status: {status}")
            rms = self._rms(indata)
            # Log only meaningful activity to avoid spam
            if rms and rms > 0.01:
                append_log(self.paths, f"Microphone activity detected RMS={rms:.4f}")
                # Lightweight keyword heuristic: when activity spikes, record an event
                try:
                    if rms > 0.05:
                        self.record_keyword_event("activity_spike")
                except Exception as e:
                    append_log(self.paths, f"Failed to record keyword event: {e}")
        except Exception as e:
            append_log(self.paths, f"Microphone callback error: {e}")

    def _run(self):
        try:
            if not self.available or not self._sd:
                return
            try:
                with self._sd.InputStream(callback=self._callback):
                    while self._running:
                        time.sleep(0.1)
            except Exception as e:
                append_log(self.paths, f"Microphone listener stream error: {e}")
        except Exception as e:
            append_log(self.paths, f"Microphone listener runtime error: {e}")

    def start(self) -> bool:
        try:
            if not self.available:
                append_log(self.paths, "Microphone listener not available; cannot start.")
                return False
            if self._running:
                return True
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            append_log(self.paths, "Microphone listener started")
            return True
        except Exception as e:
            append_log(self.paths, f"Failed to start microphone listener: {e}")
            return False

    def stop(self) -> bool:
        try:
            if not self._running:
                return True
            self._running = False
            if self._thread:
                self._thread.join(timeout=2)
            append_log(self.paths, "Microphone listener stopped")
            return True
        except Exception as e:
            append_log(self.paths, f"Failed to stop microphone listener: {e}")
            return False


class KeywordSpotter:
    """Lightweight keyword spotter using Vosk when available.
    If Vosk or a local model is not available it remains inactive but safe.
    When a keyword is detected, it records an anonymized telemetry event and
    increments local keyword counts on the MicrophoneListener.
    """
    def __init__(self, paths: IntentOSPaths, mic_listener: Optional[MicrophoneListener] = None, keywords: Optional[list] = None):
        self.paths = paths
        self.mic = mic_listener
        self.keywords = keywords or ["intentos", "assistant", "hey intentos"]
        self.available = False
        self._running = False
        self._thread = None
        self._vosk = None
        self._model = None
        try:
            try:
                import vosk
                self._vosk = vosk
            except Exception as e:
                append_log(paths, f"Vosk not available for keyword spotting: {e}")
                self._vosk = None
                return

            # look for a local small model in misc/vosk-model-small or plugins
            candidates = [
                os.path.join(paths.misc_dir, "vosk-model-small"),
                os.path.join(paths.plugins_dir, "vosk-model-small"),
            ]
            for c in candidates:
                if os.path.isdir(c):
                    try:
                        self._model = self._vosk.Model(c)
                        self.available = True
                        break
                    except Exception as e:
                        append_log(paths, f"Failed to load Vosk model at {c}: {e}")
            if not self._model:
                append_log(paths, "No Vosk model found; keyword spotting disabled.")
                self.available = False
        except Exception as e:
            append_log(paths, f"Error initializing KeywordSpotter: {e}")
            self.available = False

    def _run(self):
        try:
            if not self.available or not self._vosk or not self._model or not self.mic or not self.mic.available:
                return
            import json as _json
            rec = self._vosk.KaldiRecognizer(self._model, 16000)
            # Use sounddevice to capture audio if available
            sd = getattr(self.mic, "_sd", None)
            if not sd:
                append_log(self.paths, "sounddevice not available for keyword spotter")
                return
            with sd.InputStream(samplerate=16000, channels=1, dtype="int16") as stream:
                while self._running:
                    try:
                        data = stream.read(4000)[0]
                        if not data:
                            continue
                        if rec.AcceptWaveform(data.tobytes() if hasattr(data, 'tobytes') else bytes(data)):
                            res = _json.loads(rec.Result())
                            text = (res.get("text") or "").lower()
                            for kw in self.keywords:
                                if kw.lower() in text:
                                    try:
                                        # record occurrence
                                        if getattr(self.mic, 'record_keyword_event', None):
                                            self.mic.record_keyword_event(kw)
                                        record_telemetry_event(self.paths, {"ts": _ts(), "event": "keyword_detected", "keyword": kw})
                                        append_log(self.paths, f"Keyword spotted: {kw}")
                                    except Exception as e:
                                        append_log(self.paths, f"Error handling detected keyword '{kw}': {e}")
                    except Exception as e:
                        append_log(self.paths, f"Keyword spotter stream error: {e}")
                        time.sleep(0.5)
        except Exception as e:
            append_log(self.paths, f"Keyword spotter runtime error: {e}")

    def start(self):
        try:
            if not self.available:
                append_log(self.paths, "KeywordSpotter not available; cannot start.")
                return False
            if self._running:
                return True
            self._running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            append_log(self.paths, "KeywordSpotter started")
            return True
        except Exception as e:
            append_log(self.paths, f"Failed to start KeywordSpotter: {e}")
            return False

    def stop(self):
        try:
            if not self._running:
                return True
            self._running = False
            if self._thread:
                self._thread.join(timeout=2)
            append_log(self.paths, "KeywordSpotter stopped")
            return True
        except Exception as e:
            append_log(self.paths, f"Failed to stop KeywordSpotter: {e}")
            return False


# ============================================================================
# LOCATION (best-effort via IP geolocation)
# ============================================================================

def get_location(paths: IntentOSPaths, timeout: int = 3) -> Optional[Dict[str, Any]]:
    """Return a dict with location info (e.g., city, region, country) when consent is granted.
    Caches the latest result in config/location.json. Returns None on failure or if consent not given.
    """
    try:
        if not get_feature_consent(paths, "location"):
            append_log(paths, "Attempted to get location without consent")
            return None
        url = "https://ipinfo.io/json"
        try:
            with urlopen(url, timeout=timeout) as resp:
                if getattr(resp, "status", 200) != 200:
                    append_log(paths, f"Location service returned HTTP {getattr(resp, 'status', 'unknown')}")
                    return None
                data = json.load(resp)
                # cache
                try:
                    _safe_write_json(os.path.join(paths.config_dir, "location.json"), data)
                except Exception as e:
                    append_log(paths, f"Failed to cache location: {e}")
                return data
        except Exception as e:
            append_log(paths, f"Failed to fetch location: {e}")
            return None
    except Exception as e:
        append_log(paths, f"Error in get_location: {e}")
        return None


def load_cached_location(paths: IntentOSPaths) -> Optional[Dict[str, Any]]:
    try:
        p = os.path.join(paths.config_dir, "location.json")
        return _safe_read_json(p) or None
    except Exception as e:
        append_log(paths, f"Failed to read cached location: {e}")
        return None


# ============================================================================
# TELEMETRY (local, anonymized)
# ============================================================================

def _telemetry_path(paths: IntentOSPaths) -> str:
    return os.path.join(paths.config_dir, "telemetry.jsonl")


def record_telemetry_event(paths: IntentOSPaths, event: Dict[str, Any]) -> bool:
    """Record a small anonymized telemetry event locally (jsonl). Respects telemetry consent."""
    try:
        if not get_feature_consent(paths, "telemetry"):
            append_log(paths, "Telemetry consent not granted; skipping record")
            return False
        p = _telemetry_path(paths)
        try:
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
            return True
        except Exception as e:
            append_log(paths, f"Failed to write telemetry event: {e}")
            return False
    except Exception as e:
        append_log(paths, f"Error in record_telemetry_event: {e}")
        return False


def load_telemetry_events(paths: IntentOSPaths) -> list:
    events = []
    try:
        p = _telemetry_path(paths)
        if not os.path.exists(p):
            return events
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    events.append(json.loads(line.strip()))
                except Exception:
                    continue
    except Exception as e:
        append_log(paths, f"Failed to load telemetry events: {e}")
    return events


def clear_telemetry(paths: IntentOSPaths) -> bool:
    try:
        p = _telemetry_path(paths)
        if os.path.exists(p):
            os.remove(p)
        return True
    except Exception as e:
        append_log(paths, f"Failed to clear telemetry: {e}")
        return False


def ensure_vosk_model(paths: IntentOSPaths, auto_download: bool = False, url: Optional[str] = None) -> bool:
    """Ensure a local Vosk model directory exists.
    Returns True if a usable model is present or successfully installed.
    If `auto_download` is True and a `url` is provided, it will attempt a best-effort
    download and extract to `misc/vosk-model-small`.
    This helper is conservative and never raises; it logs failures and returns False
    when no model is available.
    """
    candidates = [
        os.path.join(paths.misc_dir, "vosk-model-small"),
        os.path.join(paths.plugins_dir, "vosk-model-small"),
    ]
    for c in candidates:
        if os.path.isdir(c):
            append_log(paths, f"Found existing Vosk model at {c}")
            return True

    if not auto_download:
        append_log(paths, "No Vosk model found and auto_download not requested.")
        return False

    # Auto-download requested: require a URL
    if not url:
        append_log(paths, "Auto-download requested but no URL provided for Vosk model.")
        return False

    try:
        tmpfile, _ = urlretrieve(url)
        append_log(paths, f"Downloaded Vosk model archive to {tmpfile}")
        # Attempt to extract zip or tar.gz
        dest = os.path.join(paths.misc_dir, "vosk-model-small")
        try:
            os.makedirs(dest, exist_ok=True)
            # Try zip first
            try:
                import zipfile
                with zipfile.ZipFile(tmpfile, 'r') as z:
                    z.extractall(dest)
                append_log(paths, f"Extracted Vosk model zip to {dest}")
                return True
            except Exception:
                pass
            # Try tar
            try:
                import tarfile
                with tarfile.open(tmpfile, 'r:*') as t:
                    t.extractall(dest)
                append_log(paths, f"Extracted Vosk model tar to {dest}")
                return True
            except Exception:
                pass
            append_log(paths, "Downloaded archive was not a recognized zip or tar file.")
            return False
        except Exception as e:
            append_log(paths, f"Failed to extract Vosk model: {e}")
            return False
    except Exception as e:
        append_log(paths, f"Failed to download Vosk model from {url}: {e}")
        return False


def run_subprocess(cmd: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """
    Safe wrapper around subprocess.run.
    Always returns a CompletedProcess-like object; never raises.
    """
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            shell=False,
        )
    except Exception as e:
        # Fabricate a CompletedProcess-like result
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr=f"Subprocess error: {e}",
        )


# ============================================================================
# FILE & ENGINE HELPERS
# ============================================================================

def backup_file(path: str, paths: Optional[IntentOSPaths] = None) -> Optional[str]:
    """
    Safe backup helper. Returns backup path or None. Never raises.
    """
    if not os.path.exists(path):
        return None
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{path}.backup_{ts}"
    try:
        with open(path, "rb") as src, open(backup_path, "wb") as dst:
            dst.write(src.read())
        if paths:
            append_log(paths, f"Backup created: {backup_path}")
        return backup_path
    except Exception as e:
        if paths:
            append_log(paths, f"Failed to create backup for {path}: {e}")
        return None


def get_engine_metadata(paths: IntentOSPaths) -> Dict[str, Any]:
    try:
        if not os.path.exists(paths.root_file):
            return {"exists": False}
        stat = os.stat(paths.root_file)
        return {
            "exists": True,
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }
    except Exception as e:
        append_log(paths, f"Failed to stat root engine: {e}")
        return {"exists": False}


# ============================================================================
# REAL-TIME BACKEND HEALTH POLLING (RESILIENT)
# ============================================================================

class BackendHealthMonitor:
    """
    Polls backend /health endpoint. Never raises; status stored in .status dict.
    """
    def __init__(self, paths: IntentOSPaths, interval: float = 5.0):
        self.paths = paths
        self.interval = interval
        self.running = False
        self.status: Dict[str, Any] = {"ok": False, "last_check": None, "error": None}
        self.thread: Optional[threading.Thread] = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            self.status["last_check"] = datetime.utcnow().isoformat()
            try:
                with urlopen("http://127.0.0.1:8000/health", timeout=2) as resp:
                    if resp.status == 200:
                        self.status["ok"] = True
                        self.status["error"] = None
                    else:
                        self.status["ok"] = False
                        self.status["error"] = f"HTTP {resp.status}"
            except HTTPError as e:
                self.status["ok"] = False
                self.status["error"] = f"HTTP error: {e.code}"
            except URLError as e:
                self.status["ok"] = False
                self.status["error"] = f"Connection error: {e.reason}"
            except Exception as e:
                self.status["ok"] = False
                self.status["error"] = f"Error: {e}"
            time.sleep(self.interval)


# ============================================================================
# THEME
# ============================================================================

class IntentOSTheme:
    THEMES = {
        "Neo Cyan": {
            "BG": "#020617",
            "SIDEBAR_BG": "#030712",
            "CARD_BG": "#0b1120",
            "CARD_ALT_BG": "#020617",
            "ACCENT": "#38bdf8",
            "ACCENT_SOFT": "#0ea5e9",
            "ACCENT_MUTED": "#7dd3fc",
        },
        "Violet Pulse": {
            "BG": "#050016",
            "SIDEBAR_BG": "#090021",
            "CARD_BG": "#13043b",
            "CARD_ALT_BG": "#050016",
            "ACCENT": "#a855f7",
            "ACCENT_SOFT": "#c084fc",
            "ACCENT_MUTED": "#e9d5ff",
        },
        "Amber Core": {
            "BG": "#0a0700",
            "SIDEBAR_BG": "#120c00",
            "CARD_BG": "#1c1303",
            "CARD_ALT_BG": "#0a0700",
            "ACCENT": "#f59e0b",
            "ACCENT_SOFT": "#fbbf24",
            "ACCENT_MUTED": "#fed7aa",
        },
    }

    BG = "#020617"
    SIDEBAR_BG = "#030712"
    CARD_BG = "#0b1120"
    CARD_ALT_BG = "#020617"
    ACCENT = "#38bdf8"
    ACCENT_SOFT = "#0ea5e9"
    ACCENT_MUTED = "#7dd3fc"

    TEXT_PRIMARY = "#e5e7eb"
    TEXT_MUTED = "#9ca3af"
    TEXT_SUBTLE = "#6b7280"

    SUCCESS = "#4ade80"
    WARNING = "#facc15"
    DANGER = "#f97373"

    @classmethod
    def apply_theme(cls, name: str) -> None:
        theme = cls.THEMES.get(name)
        if not theme:
            return
        cls.BG = theme["BG"]
        cls.SIDEBAR_BG = theme["SIDEBAR_BG"]
        cls.CARD_BG = theme["CARD_BG"]
        cls.CARD_ALT_BG = theme["CARD_ALT_BG"]
        cls.ACCENT = theme["ACCENT"]
        cls.ACCENT_SOFT = theme["ACCENT_SOFT"]
        cls.ACCENT_MUTED = theme["ACCENT_MUTED"]


# ============================================================================
# BASE PAGE + LABEL HELPERS
# ============================================================================

class BasePage(ttk.Frame):
    def __init__(self, master: ttk.Frame, app: "IntentOSGUI"):
        super().__init__(master, style="Main.TFrame")
        self.app = app


def _label_side(parent, text: str, font=("Segoe UI", 9), fg=None, bg=None):
    if fg is None:
        fg = IntentOSTheme.TEXT_SUBTLE
    if bg is None:
        bg = IntentOSTheme.SIDEBAR_BG
    return tk.Label(parent, text=text, font=font, fg=fg, bg=bg)


def _label_card(parent, text: str, style="TLabel", font=("Segoe UI", 10)):
    lbl = ttk.Label(parent, text=text, style=style)
    lbl.configure(font=font)
    return lbl


# ============================================================================
# MAIN GUI CLASS (CORE LAYOUT, THEME, MAINTENANCE)
# ============================================================================

class IntentOSGUI(tk.Tk):
    def __init__(self, repo_root: str):
        super().__init__()

        self.paths = IntentOSPaths(repo_root)
        self.owner = load_owner(self.paths)
        self.listening_state = load_listening_state(self.paths)
        self.maintenance_state = load_maintenance_state(self.paths)
        self.permissions = load_permissions(self.paths)

        self.current_theme = "Neo Cyan"
        IntentOSTheme.apply_theme(self.current_theme)

        self.backend_monitor = BackendHealthMonitor(self.paths)
        self.backend_monitor.start()

        # Microphone listener (best-effort)
        try:
            self.microphone_listener = MicrophoneListener(self.paths)
        except Exception as e:
            append_log(self.paths, f"Failed to initialize MicrophoneListener: {e}")
            self.microphone_listener = None

        # Keyword spotter (optional, using Vosk)
        try:
            self.keyword_spotter = KeywordSpotter(self.paths, self.microphone_listener)
        except Exception as e:
            append_log(self.paths, f"Failed to initialize KeywordSpotter: {e}")
            self.keyword_spotter = None

        self.pages: Dict[str, BasePage] = {}
        self.current_page: Optional[BasePage] = None

        self.title("IntentOS Owner Console")
        self.geometry("1380x840")
        self.minsize(1200, 720)

        self._setup_style()
        self._build_layout()
        # pages are created later after class definitions; see subsequent blocks

        append_log(self.paths, "Owner console GUI launched.")
        append_audit(self.paths, "Owner console GUI launched.")

        # apply microphone consent if already granted
        try:
            if get_feature_consent(self.paths, "microphone"):
                state = load_listening_state(self.paths)
                if state.enabled and self.microphone_listener:
                    try:
                        self.microphone_listener.start()
                    except Exception as e:
                        append_log(self.paths, f"Failed to start microphone on launch: {e}")
        except Exception as e:
            append_log(self.paths, f"Error applying microphone consent on launch: {e}")

        self.after(2000, self._refresh_backend_status_indicator)
        self.after(1000, self._tick_maintenance_countdown)
        # prompt for initial consents shortly after GUI ready
        self.after(1500, self._prompt_initial_consents)

        # Helpers: microphone test, temporary pause, and opening OS microphone settings
        def _test_microphone(self):
            try:
                if not getattr(self, 'microphone_listener', None) or not self.microphone_listener.available:
                    if messagebox.askyesno('Microphone Test', 'Microphone support is not available. Open OS microphone settings?'):
                        self._open_os_microphone_settings()
                    return False
                sd = getattr(self.microphone_listener, '_sd', None)
                if not sd:
                    messagebox.showerror('Microphone Test', 'sounddevice not available in this environment.')
                    return False
                recorded = []
                def cb(indata, frames, t, status):
                    recorded.append(1)
                try:
                    with sd.InputStream(callback=cb, channels=1, samplerate=16000):
                        time.sleep(0.8)
                    messagebox.showinfo('Microphone Test', 'Microphone appears to be working (short capture succeeded).')
                    append_audit(self.paths, 'Microphone test successful via UI')
                    return True
                except Exception as e:
                    append_log(self.paths, f"Microphone test failed: {e}")
                    if messagebox.askyesno('Microphone Test Failed', 'Open OS microphone settings to troubleshoot?'):
                        self._open_os_microphone_settings()
                    return False
            except Exception as e:
                append_log(self.paths, f"Error during microphone test: {e}")
                return False

        def _pause_listening(self, minutes: int = 5):
            try:
                self._set_listening_enabled(False)
                append_audit(self.paths, f'Listening paused for {minutes} minutes')
                self.after(minutes * 60 * 1000, lambda: (self._set_listening_enabled(True), append_audit(self.paths, f'Listening resumed after {minutes} minutes')))
                return True
            except Exception as e:
                append_log(self.paths, f"Failed to pause listening: {e}")
                return False

        def _open_os_microphone_settings(self):
            try:
                if sys.platform.startswith('win'):
                    try:
                        subprocess.Popen(['powershell', '-NoProfile', '-Command', 'Start-Process ms-settings:privacy-microphone'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        return True
                    except Exception:
                        try:
                            os.startfile('ms-settings:privacy-microphone')
                            return True
                        except Exception:
                            pass
                elif sys.platform.startswith('darwin'):
                    try:
                        subprocess.Popen(['open', 'x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        return True
                    except Exception:
                        pass
                else:
                    messagebox.showinfo('Microphone Settings', 'Please check your system settings for microphone permissions (e.g., GNOME Settings -> Privacy -> Microphone).')
                    return True
                return False
            except Exception as e:
                append_log(self.paths, f"Failed to open OS microphone settings: {e}")
                return False
        # start automatic suggestion generation (runs periodically)
        self.after(10000, self._auto_suggestion_tick)

    def _set_listening_enabled(self, enabled: bool):
        """Enable or disable microphone listening and persist the change."""
        try:
            state = load_listening_state(self.paths)
            state.enabled = bool(enabled)
            save_listening_state(self.paths, state)
            if enabled:
                if getattr(self, "microphone_listener", None):
                    try:
                        self.microphone_listener.start()
                    except Exception as e:
                        append_log(self.paths, f"Failed to start microphone listener: {e}")
                if getattr(self, "keyword_spotter", None):
                    try:
                        self.keyword_spotter.start()
                    except Exception as e:
                        append_log(self.paths, f"Failed to start keyword spotter: {e}")
            else:
                if getattr(self, "microphone_listener", None):
                    try:
                        self.microphone_listener.stop()
                    except Exception as e:
                        append_log(self.paths, f"Failed to stop microphone listener: {e}")
                if getattr(self, "keyword_spotter", None):
                    try:
                        self.keyword_spotter.stop()
                    except Exception as e:
                        append_log(self.paths, f"Failed to stop keyword spotter: {e}")
            append_log(self.paths, f"Listening enabled set to {enabled} via UI")
        except Exception as e:
            append_log(self.paths, f"Failed to set listening enabled: {e}")

    def _prompt_initial_consents(self):
        """Prompt the operator to grant microphone and location consents on first run.
        This is shown as a modal dialog; it writes consents and enables listening when microphone consent is given.
        """
        try:
            features = self.permissions.get("features", {})
            mic_info = features.get("microphone", {})
            loc_info = features.get("location", {})
            need_prompt = (not bool(mic_info.get("consent_given", False))) or (not bool(loc_info.get("consent_given", False)))
            if not need_prompt:
                return

            top = tk.Toplevel(self)
            top.title("Permissions needed")
            top.transient(self)
            top.grab_set()

            card = ttk.Frame(top, padding=12)
            card.pack(fill="both", expand=True)

            ttk.Label(
                card,
                text=(
                    "IntentOS can improve accuracy with microphone and location data. If you consent to the microphone it will be always-listening by default, but you may disable listening anytime in Settings.\n\n"
                    "Without your data, IntentOS may not function as intended."
                ),
                style="Muted.TLabel",
                wraplength=680,
                justify="left",
            ).pack(anchor="w", pady=(0, 8))

            mic_var = tk.BooleanVar(value=bool(mic_info.get("consent_given", False)))
            ttk.Checkbutton(card, text=f"Microphone - {mic_info.get('description','')}", variable=mic_var).pack(anchor="w", padx=6, pady=2)
            ttk.Label(card, text="Note: consenting to the microphone will cause the app to listen by default; you can later disable listening.", style="Muted.TLabel", wraplength=640).pack(anchor="w", padx=6)

            loc_var = tk.BooleanVar(value=bool(loc_info.get("consent_given", False)))
            ttk.Checkbutton(card, text=f"Location - {loc_info.get('description','')}", variable=loc_var).pack(anchor="w", padx=6, pady=6)

            btn_frame = ttk.Frame(card)
            btn_frame.pack(fill="x", pady=(8, 0))

            def _save():
                owner_pass = None
                errors = []
                for key, var in (("microphone", mic_var), ("location", loc_var)):
                    try:
                        ok = set_feature_consent(self.paths, key, bool(var.get()), owner_passphrase=None)
                        if not ok:
                            errors.append(key)
                    except Exception as e:
                        append_log(self.paths, f"Error setting consent for {key}: {e}")
                        errors.append(key)

                if errors:
                    messagebox.showerror("Consent Failed", f"Could not set consent for: {', '.join(errors)}")
                    return

                try:
                    if mic_var.get():
                        self._set_listening_enabled(True)
                    else:
                        self._set_listening_enabled(False)
                except Exception as e:
                    append_log(self.paths, f"Error applying listening state after consent prompt: {e}")

                append_audit(self.paths, "Initial consents set via prompt")
                top.destroy()

            ttk.Button(btn_frame, text="Save", style="Accent.TButton", command=_save).pack(side="right", padx=(8, 0))
            ttk.Button(btn_frame, text="Cancel", style="Subtle.TButton", command=top.destroy).pack(side="right")
        except Exception as e:
            append_log(self.paths, f"Error displaying initial consent prompt: {e}")

    def _install_vosk_model_ui(self) -> bool:
        """Operator-driven install UI for a Vosk model archive.
        Prompts for a URL, asks for explicit confirmation, then attempts a best-effort download
        and extraction via `ensure_vosk_model(paths, auto_download=True, url=...)`.
        Returns True on success, False otherwise. Always logs and shows user-facing dialogs on failure.
        """
        try:
            url = simpledialog.askstring("Install Vosk model", "Enter URL to Vosk model archive (zip or tar.gz):")
            if not url:
                return False
            confirm = messagebox.askyesno(
                "Confirm Vosk Model Install",
                f"Download and install model from:\n{url}?\nThis may be large and use network data.")
            if not confirm:
                return False
            append_log(self.paths, f"Operator requested Vosk model install from {url}")
            ok = ensure_vosk_model(self.paths, auto_download=True, url=url)
            if ok:
                messagebox.showinfo("Model Installed", "Vosk model installed successfully. Enable keyword spotting in Settings or restart the app.")
                append_log(self.paths, "Vosk model installed successfully via UI.")
                return True
            else:
                messagebox.showerror("Install Failed", "Failed to download or extract Vosk model. Check logs for details.")
                append_log(self.paths, "Vosk model install failed via UI.")
                return False
        except Exception as e:
            append_log(self.paths, f"Error during Vosk model install UI: {e}")
            return False

    # ----------------------------------------------------------------------
    # STYLE
    # ----------------------------------------------------------------------

    def _setup_style(self):
        self.configure(bg=IntentOSTheme.BG)
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Sidebar.TFrame", background=IntentOSTheme.SIDEBAR_BG)
        style.configure("Main.TFrame", background=IntentOSTheme.BG)
        style.configure("Card.TFrame", background=IntentOSTheme.CARD_BG)
        style.configure("AltCard.TFrame", background=IntentOSTheme.CARD_ALT_BG)

        style.configure("Nav.TButton",
                        background=IntentOSTheme.SIDEBAR_BG,
                        foreground=IntentOSTheme.TEXT_MUTED,
                        padding=10,
                        anchor="w",
                        relief="flat")
        style.map("Nav.TButton",
                  background=[("active", "#0f172a")],
                  foreground=[("active", IntentOSTheme.TEXT_PRIMARY)])

        style.configure("Accent.TButton",
                        background=IntentOSTheme.ACCENT,
                        foreground="black",
                        padding=8,
                        relief="flat")
        style.map("Accent.TButton",
                  background=[("active", IntentOSTheme.ACCENT_SOFT)])

        style.configure("Subtle.TButton",
                        background="#111827",
                        foreground=IntentOSTheme.TEXT_MUTED,
                        padding=6,
                        relief="flat")
        style.map("Subtle.TButton",
                  background=[("active", "#1f2937")],
                  foreground=[("active", IntentOSTheme.TEXT_PRIMARY)])

        style.configure("TLabel", background=IntentOSTheme.CARD_BG,
                        foreground=IntentOSTheme.TEXT_PRIMARY)
        style.configure("Muted.TLabel", background=IntentOSTheme.CARD_BG,
                        foreground=IntentOSTheme.TEXT_MUTED)
        style.configure("Danger.TLabel", background=IntentOSTheme.CARD_BG,
                        foreground=IntentOSTheme.DANGER)
        style.configure("Success.TLabel", background=IntentOSTheme.CARD_BG,
                        foreground=IntentOSTheme.SUCCESS)
        style.configure("Warning.TLabel", background=IntentOSTheme.CARD_BG,
                        foreground=IntentOSTheme.WARNING)

        style.configure("Maintenance.TLabel", background="#7c2d12",
                        foreground="#fed7aa")
        style.configure("Maintenance.TFrame", background="#7c2d12")

    # ----------------------------------------------------------------------
    # LAYOUT
    # ----------------------------------------------------------------------

    def _build_layout(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0)  # maintenance banner row
        self.grid_rowconfigure(1, weight=1)

        # Maintenance banner
        self.maintenance_banner = ttk.Frame(self, style="Maintenance.TFrame")
        self.maintenance_banner.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.maintenance_label = ttk.Label(
            self.maintenance_banner,
            text="",
            style="Maintenance.TLabel",
            anchor="w",
        )
        self.maintenance_label.pack(side="left", padx=10, pady=2)
        self.maintenance_banner.grid_remove()

        # Sidebar + main container
        content_frame = ttk.Frame(self, style="Main.TFrame")
        content_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        content_frame.grid_columnconfigure(0, weight=0)
        content_frame.grid_columnconfigure(1, weight=1)
        content_frame.grid_rowconfigure(0, weight=1)

        self.sidebar = ttk.Frame(content_frame, style="Sidebar.TFrame")
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.configure(width=260)

        self.main_container = ttk.Frame(content_frame, style="Main.TFrame")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=12, pady=12)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

    def _build_sidebar(self):
        # Header
        top = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        top.pack(fill="x", pady=(12, 8), padx=12)

        title = tk.Label(
            top,
            text="IntentOS",
            font=("Segoe UI Semibold", 20),
            fg=IntentOSTheme.ACCENT_MUTED,
            bg=IntentOSTheme.SIDEBAR_BG,
        )
        title.pack(anchor="w")

        subtitle = _label_side(
            top,
            "Owner Console",
            font=("Segoe UI", 10),
        )
        subtitle.pack(anchor="w")

        # Orb avatar
        orb_frame = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        orb_frame.pack(fill="x", padx=12, pady=(8, 8))

        self.orb_canvas = tk.Canvas(
            orb_frame,
            width=64,
            height=64,
            bg=IntentOSTheme.SIDEBAR_BG,
            highlightthickness=0,
        )
        self.orb_canvas.pack(anchor="w")
        self._draw_orb()

        # Theme selector
        theme_row = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        theme_row.pack(fill="x", padx=12, pady=(0, 8))

        tk.Label(
            theme_row,
            text="Theme",
            font=("Segoe UI", 8),
            fg=IntentOSTheme.TEXT_SUBTLE,
            bg=IntentOSTheme.SIDEBAR_BG,
        ).pack(anchor="w")

        self.theme_var = tk.StringVar(value=self.current_theme)
        theme_menu = ttk.Combobox(
            theme_row,
            textvariable=self.theme_var,
            values=list(IntentOSTheme.THEMES.keys()),
            state="readonly",
            width=18,
        )
        theme_menu.pack(anchor="w", pady=(2, 0))
        theme_menu.bind("<<ComboboxSelected>>", self._on_theme_change)

        # Backend status line
        status_frame = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        status_frame.pack(fill="x", padx=12, pady=(4, 8))

        self.backend_status_label = _label_side(
            status_frame,
            "Backend: checking...",
            font=("Segoe UI", 9),
        )
        self.backend_status_label.pack(anchor="w")

        # Navigation buttons (pages will be created later)
        self.nav_frame = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        self.nav_frame.pack(fill="x", padx=6, pady=(8, 8))
        self.nav_buttons: Dict[str, ttk.Button] = {}

        # Footer
        footer = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        footer.pack(side="bottom", fill="x", padx=8, pady=10)

        owner_text = (
            "Unclaimed instance"
            if self.owner is None
            else f"Owner: {self.owner.name}"
        )
        owner_label = _label_side(
            footer,
            owner_text,
            font=("Segoe UI", 9),
        )
        owner_label.pack(anchor="w")

        path_label = _label_side(
            footer,
            self.paths.repo_root,
            font=("Consolas", 8),
            fg="#4b5563",
        )
        path_label.pack(anchor="w")

    # ----------------------------------------------------------------------
    # PAGE REGISTRATION (CALLED LATER)
    # ----------------------------------------------------------------------

    def register_page(self, name: str, frame: BasePage, label: str):
        """
        Register a page and create corresponding nav button.
        """
        self.pages[name] = frame
        btn = ttk.Button(
            self.nav_frame,
            text=label,
            style="Nav.TButton",
            command=lambda n=name: self.show_page(n),
        )
        btn.pack(fill="x", pady=2, padx=4)
        self.nav_buttons[name] = btn

    def show_page(self, name: str):
        """
        Show a registered page. Logs on error; never crashes.
        """
        try:
            if self.current_page:
                self.current_page.pack_forget()
            page = self.pages.get(name)
            if not page:
                append_log(self.paths, f"Attempt to show unknown page: {name}")
                return
            page.pack(fill="both", expand=True)
            self.current_page = page
        except Exception as e:
            append_log(self.paths, f"Failed to show page {name}: {e}")
            messagebox.showerror("Page Error", f"Failed to show page '{name}'. See logs for details.")

    # ----------------------------------------------------------------------
    # THEME / ORB / STATUS / MAINTENANCE
    # ----------------------------------------------------------------------

    def _refresh_backend_status_indicator(self):
        try:
            status = self.backend_monitor.status
            if status["ok"]:
                text = "Backend: online"
                color = IntentOSTheme.SUCCESS
            else:
                err = status.get("error") or "offline"
                text = f"Backend: {err}"
                color = IntentOSTheme.DANGER
            self.backend_status_label.config(fg=color, text=text)
        except Exception as e:
            append_log(self.paths, f"Error updating backend status label: {e}")
        finally:
            self.after(3000, self._refresh_backend_status_indicator)

    def _on_theme_change(self, *_):
        try:
            self.current_theme = self.theme_var.get()
            IntentOSTheme.apply_theme(self.current_theme)
            self._setup_style()
            self._redraw_all()
            append_log(self.paths, f"Theme changed to {self.current_theme}")
            append_audit(self.paths, f"Theme changed to {self.current_theme}")
        except Exception as e:
            append_log(self.paths, f"Failed to apply theme: {e}")
            messagebox.showerror("Theme Error", f"Failed to apply theme: {e}")

    def _draw_orb(self):
        try:
            c = self.orb_canvas
            c.delete("all")
            w = int(c["width"])
            h = int(c["height"])
            r = min(w, h) // 2 - 4
            cx, cy = w // 2, h // 2

            c.create_oval(
                cx - r - 6, cy - r - 6, cx + r + 6, cy + r + 6,
                fill=IntentOSTheme.CARD_BG, outline=""
            )
            c.create_oval(
                cx - r, cy - r, cx + r, cy + r,
                fill=IntentOSTheme.ACCENT, outline=""
            )
            c.create_oval(
                cx - r // 2, cy - r // 2, cx + r // 2, cy + r // 2,
                fill=IntentOSTheme.ACCENT_MUTED, outline=""
            )
        except Exception as e:
            append_log(self.paths, f"Failed to draw orb: {e}")

    def _redraw_all(self):
        try:
            self.configure(bg=IntentOSTheme.BG)
            self._draw_orb()
        except Exception as e:
            append_log(self.paths, f"Redraw error: {e}")

    # --- Maintenance countdown and completion ---

    def _tick_maintenance_countdown(self):
        try:
            ms = self.maintenance_state
            if ms.enabled and ms.started_at:
                start = None
                try:
                    start = datetime.fromisoformat(ms.started_at.replace("Z", ""))
                except Exception as e:
                    append_log(self.paths, f"Invalid maintenance start time, disabling: {e}")
                    ms.enabled = False
                    ms.started_at = None
                    save_maintenance_state(self.paths, ms)
                    self._hide_maintenance_banner()
                    self.after(1000, self._tick_maintenance_countdown)
                    return

                end = start + timedelta(seconds=ms.duration_seconds)
                now = datetime.utcnow()
                if now >= end:
                    ms.enabled = False
                    ms.started_at = None
                    save_maintenance_state(self.paths, ms)
                    append_log(self.paths, "Maintenance window completed.")
                    append_audit(self.paths, "Maintenance window completed.")
                    self._hide_maintenance_banner()
                    messagebox.showinfo(
                        "Maintenance Complete",
                        "Maintenance is complete.\nAll updates have been applied.\n"
                        "The console will now restart to apply changes."
                    )
                    self._restart_console()
                    return
                else:
                    remaining = end - now
                    minutes, seconds = divmod(int(remaining.total_seconds()), 60)
                    msg = f"Maintenance active — ends in {minutes}m {seconds}s (auto-refresh when done)."
                    self._show_maintenance_banner(msg)
            else:
                self._hide_maintenance_banner()
        except Exception as e:
            append_log(self.paths, f"Maintenance countdown error: {e}")
        finally:
            self.after(1000, self._tick_maintenance_countdown)

    def _show_maintenance_banner(self, msg: str):
        try:
            self.maintenance_label.config(text=msg)
            self.maintenance_banner.grid()
        except Exception as e:
            append_log(self.paths, f"Failed to show maintenance banner: {e}")

    def _hide_maintenance_banner(self):
        try:
            self.maintenance_banner.grid_remove()
        except Exception as e:
            append_log(self.paths, f"Failed to hide maintenance banner: {e}")

    def _restart_console(self):
        """
        Self-restart the GUI process. Best effort; never raises.
        """
        try:
            python = sys.executable
            script = os.path.abspath(sys.argv[0])
            subprocess.Popen([python, script], cwd=os.path.dirname(script))
        except Exception as e:
            append_log(self.paths, f"Failed to restart console: {e}")
        finally:
            try:
                self.destroy()
            except Exception:
                pass

# ============================================================================
# OVERVIEW PAGE
# ============================================================================

class OverviewPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # --- Instance & Ownership ---
        owner_card = ttk.Frame(self, style="Card.TFrame")
        owner_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 8))

        _label_card(owner_card, "Instance & Ownership",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        if self.app.owner is None:
            ttk.Label(
                owner_card,
                text=(
                    "This IntentOS instance has no registered Owner.\n\n"
                    "The first user to register becomes the permanent Owner.\n"
                    "Ownership cannot be changed from this console."
                ),
                style="Muted.TLabel",
                wraplength=420,
                justify="left",
            ).pack(anchor="w", padx=12, pady=(0, 8))

            ttk.Button(
                owner_card,
                text="Register Owner",
                style="Accent.TButton",
                command=self._register_owner_dialog,
            ).pack(anchor="e", padx=12, pady=(0, 12))

        else:
            ttk.Label(
                owner_card,
                text=(
                    f"Owner: {self.app.owner.name}\n\n"
                    "This console exposes advanced, owner-only controls.\n"
                    "Ownership is locked to this identity."
                ),
                style="Muted.TLabel",
                wraplength=420,
                justify="left",
            ).pack(anchor="w", padx=12, pady=(0, 8))

            ttk.Label(
                owner_card,
                text="Owner privileges are locked.",
                style="Success.TLabel",
            ).pack(anchor="w", padx=12, pady=(0, 12))

            # Owner-only actions: show role (passphrase-protected) and manage owner permissions
            row2 = ttk.Frame(owner_card, style="Card.TFrame")
            row2.pack(fill="x", pady=(4, 8))

            def _show_role():
                pwd = simpledialog.askstring("Owner passphrase", "Enter Owner passphrase to reveal role:", show="*")
                if not pwd:
                    return
                role = get_owner_role(self.app.paths, pwd)
                if role:
                    messagebox.showinfo("Owner Role", f"Owner role: {role}")
                else:
                    messagebox.showerror("Access Denied", "Incorrect passphrase or owner not set.")

            def _manage_owner_permissions():
                pwd = simpledialog.askstring("Owner passphrase", "Enter Owner passphrase to edit permissions:", show="*")
                if not pwd or not verify_owner_passphrase(self.app.paths, pwd):
                    messagebox.showerror("Access Denied", "Incorrect passphrase or owner not set.")
                    return
                owner = load_owner(self.app.paths)
                current = json.dumps(owner.permissions, indent=2)
                dlg = tk.Toplevel(self)
                dlg.title("Manage Owner Permissions")
                dlg.geometry("600x420")
                txt = scrolledtext.ScrolledText(dlg, wrap="word")
                txt.pack(fill="both", expand=True, padx=8, pady=8)
                txt.delete("1.0", tk.END)
                txt.insert(tk.END, current)

                def _save():
                    try:
                        data = json.loads(txt.get("1.0", tk.END))
                        set_owner_permissions(self.app.paths, owner, data)
                        messagebox.showinfo("Permissions Saved", "Owner permissions updated.")
                        dlg.destroy()
                    except Exception as e:
                        messagebox.showerror("Save Error", f"Failed to parse/save permissions: {e}")

                btn_row = ttk.Frame(dlg, style="Card.TFrame")
                btn_row.pack(fill="x", padx=8, pady=(0,8))
                ttk.Button(btn_row, text="Cancel", command=dlg.destroy, style="Subtle.TButton").pack(side="left")
                ttk.Button(btn_row, text="Save", command=_save, style="Accent.TButton").pack(side="right")

            ttk.Button(row2, text="Show Role", style="Subtle.TButton", command=_show_role).pack(side="left")
            ttk.Button(row2, text="Manage Owner Permissions", style="Accent.TButton", command=_manage_owner_permissions).pack(side="right")

        # --- System Snapshot ---
        sys_card = ttk.Frame(self, style="Card.TFrame")
        sys_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=(0, 8))

        _label_card(sys_card, "System Snapshot",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        checks = [
            ("Root engine present", os.path.exists(self.app.paths.root_file)),
            ("Backend scaffold", os.path.exists(self.app.paths.backend_main)),
            ("Dashboard scaffold", os.path.exists(self.app.paths.dashboard_index)),
            ("CLI scaffold", os.path.exists(self.app.paths.cli_script)),
            ("Owner registered", self.app.owner is not None),
            ("Always listening consent", self.app.listening_state.consent_given),
            ("Always listening enabled", self.app.listening_state.enabled),
            ("Maintenance mode", self.app.maintenance_state.enabled),
        ]

        for label, ok in checks:
            style_name = "Success.TLabel" if ok else "Warning.TLabel"
            prefix = "●" if ok else "○"
            ttk.Label(sys_card, text=f"{prefix} {label}",
                      style=style_name).pack(anchor="w", padx=12)

        actions = ttk.Frame(sys_card, style="Card.TFrame")
        actions.pack(fill="x", padx=12, pady=(10, 12))

        ttk.Button(
            actions,
            text="Engine & Services",
            style="Accent.TButton",
            command=lambda: self.app.show_page("engine"),
        ).pack(side="left")

        ttk.Button(
            actions,
            text="Data Sharing",
            style="Subtle.TButton",
            command=lambda: self.app.show_page("sharing"),
        ).pack(side="right")

    # --- Owner Registration Dialog ---
    def _register_owner_dialog(self):
        if self.app.owner is not None:
            messagebox.showinfo(
                "Owner Already Registered",
                f"This instance is already owned by '{self.app.owner.name}'."
            )
            return

        dialog = tk.Toplevel(self)
        dialog.title("Register Owner")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg=IntentOSTheme.BG)
        dialog.geometry("420x260")

        frame = ttk.Frame(dialog, style="Card.TFrame")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        _label_card(frame, "Register Owner",
                    font=("Segoe UI Semibold", 14)).pack(anchor="w",
                    pady=(4, 4))

        ttk.Label(
            frame,
            text=(
                "You are about to claim Owner status for this IntentOS instance.\n"
                "This cannot be undone from this console."
            ),
            style="Muted.TLabel",
            wraplength=380,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        name_var = tk.StringVar()
        pass_var = tk.StringVar()

        ttk.Label(frame, text="Owner name:").pack(anchor="w")
        ttk.Entry(frame, textvariable=name_var).pack(fill="x", pady=(0, 6))

        ttk.Label(frame, text="Owner passphrase:").pack(anchor="w")
        ttk.Entry(frame, textvariable=pass_var, show="*").pack(fill="x", pady=(0, 8))

        def submit():
            name = name_var.get().strip()
            pw = pass_var.get().strip()
            if not name:
                messagebox.showwarning("Owner Registration", "Please enter a name.")
                return

            if not messagebox.askyesno(
                "Confirm Owner Registration",
                f"Register '{name}' as Owner of this IntentOS instance?"
            ):
                return

            self.app.owner = OwnerInfo(name=name, passphrase=pw)
            save_owner(self.app.paths, self.app.owner)
            append_log(self.app.paths, f"Owner '{name}' registered via GUI.")
            append_audit(self.app.paths, f"Owner '{name}' registered.")
            messagebox.showinfo("Owner Registration",
                                "Owner registered. Restart console.")
            dialog.destroy()
            self.app.destroy()

        row = ttk.Frame(frame, style="Card.TFrame")
        row.pack(fill="x", pady=(4, 4))

        ttk.Button(row, text="Cancel",
                   style="Subtle.TButton",
                   command=dialog.destroy).pack(side="left")

        ttk.Button(row, text="Confirm Owner",
                   style="Accent.TButton",
                   command=submit).pack(side="right")
        
# ============================================================================
# ENGINE & SERVICES PAGE
# ============================================================================

class EngineServicesPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # --- Engine & Core ---
        engine_card = ttk.Frame(self, style="Card.TFrame")
        engine_card.grid(row=0, column=0, sticky="nsew",
                         padx=(0, 8), pady=(0, 8))

        _label_card(engine_card, "Engine & Core",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            engine_card,
            text=(
                "The root engine is the canonical IntentOS brain.\n"
                "You can run CLI diagnostics or force a GitHub sync."
            ),
            style="Muted.TLabel",
            wraplength=420,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # --- CLI Status Button ---
        row = ttk.Frame(engine_card, style="Card.TFrame")
        row.pack(fill="x", padx=12, pady=(4, 4))

        ttk.Button(
            row,
            text="Run CLI Status",
            style="Subtle.TButton",
            command=self._run_cli_status,
        ).pack(side="left")

        ttk.Button(
            row,
            text="Force Root Sync (Owner)",
            style="Accent.TButton",
            command=self._force_root_sync,
        ).pack(side="right")

        # --- Progress Bar ---
        self.progress = ttk.Progressbar(
            engine_card,
            orient="horizontal",
            mode="determinate",
            length=300
        )
        self.progress.pack(anchor="w", padx=12, pady=(4, 4))

        # --- CLI Output ---
        self.cli_output = scrolledtext.ScrolledText(
            engine_card,
            wrap="word",
            height=10,
            bg="#020617",
            fg=IntentOSTheme.TEXT_PRIMARY,
            insertbackground=IntentOSTheme.TEXT_PRIMARY,
        )
        self.cli_output.pack(fill="both", expand=True,
                             padx=12, pady=(4, 12))

        # --- Services ---
        svc_card = ttk.Frame(self, style="Card.TFrame")
        svc_card.grid(row=0, column=1, sticky="nsew",
                      padx=(8, 0), pady=(0, 8))

        _label_card(svc_card, "Services",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            svc_card,
            text="Manage backend and dashboard services.",
            style="Muted.TLabel",
            wraplength=420,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # --- Backend Controls ---
        row1 = ttk.Frame(svc_card, style="Card.TFrame")
        row1.pack(fill="x", padx=12, pady=(2, 2))

        ttk.Button(
            row1,
            text="Start Backend",
            style="Accent.TButton",
            command=self._start_backend,
        ).pack(side="left")

        ttk.Button(
            row1,
            text="Stop Backend",
            style="Subtle.TButton",
            command=self._stop_backend,
        ).pack(side="right")

        row2 = ttk.Frame(svc_card, style="Card.TFrame")
        row2.pack(fill="x", padx=12, pady=(2, 2))

        ttk.Button(
            row2,
            text="Restart Backend",
            style="Accent.TButton",
            command=self._restart_backend,
        ).pack(side="left")

        ttk.Button(
            row2,
            text="Open Dashboard",
            style="Subtle.TButton",
            command=self._open_dashboard,
        ).pack(side="right")

        # --- Backend Progress Bar ---
        self.backend_progress = ttk.Progressbar(
            svc_card,
            orient="horizontal",
            mode="determinate",
            length=300
        )
        self.backend_progress.pack(anchor="w", padx=12, pady=(4, 12))

    # ----------------------------------------------------------------------
    # CLI STATUS (with progress bar)
    # ----------------------------------------------------------------------

    def _run_cli_status(self):
        self.cli_output.delete("1.0", tk.END)
        self.progress["value"] = 0

        if not os.path.exists(self.app.paths.cli_script):
            self.cli_output.insert(tk.END, "CLI script not found.\n")
            append_log(self.app.paths, "CLI script missing.")
            return

        # Simulated progress
        for i in range(0, 101, 20):
            self.progress["value"] = i
            self.progress.update()
            time.sleep(0.1)

        proc = run_subprocess(
            [sys.executable, os.path.basename(self.app.paths.cli_script), "--status"],
            cwd=os.path.dirname(self.app.paths.cli_script),
        )

        if proc.stdout:
            self.cli_output.insert(tk.END, proc.stdout)
        if proc.stderr:
            self.cli_output.insert(tk.END, "\n[stderr]\n" + proc.stderr)

        append_log(self.app.paths, "CLI status executed via GUI.")
        append_audit(self.app.paths, "CLI status executed.")

    # ----------------------------------------------------------------------
    # ROOT SYNC (with progress bar + resilient GitHub fetch)
    # ----------------------------------------------------------------------

    def _force_root_sync(self):
        if self.app.owner is None:
            messagebox.showerror("Owner Only",
                                 "Only the Owner can sync the root engine.")
            return

        if self.app.maintenance_state.enabled:
            messagebox.showerror("Maintenance Active",
                                 "Cannot sync during maintenance mode.")
            return

        if not messagebox.askyesno(
            "Force Root Sync",
            "Fetch latest root from GitHub and overwrite local root?"
        ):
            return

        self.progress["value"] = 0
        self.progress.update()

        url = "https://raw.githubusercontent.com/adreinmorin-design/Intentos/main/root"

        try:
            for i in range(0, 60, 10):
                self.progress["value"] = i
                self.progress.update()
                time.sleep(0.1)

            with urlopen(url) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                content = resp.read()

            self.progress["value"] = 80
            self.progress.update()

            with open(self.app.paths.root_file, "wb") as f:
                f.write(content)

            self.progress["value"] = 100
            self.progress.update()

        except Exception as e:
            messagebox.showerror("Sync Failed", str(e))
            append_log(self.app.paths, f"Root sync failed: {e}")
            append_audit(self.app.paths, f"Root sync failed: {e}")
            return

        append_log(self.app.paths, "Root engine synced via GUI.")
        append_audit(self.app.paths, "Root engine synced from GitHub.")
        messagebox.showinfo("Root Sync", "Root engine synced successfully.")

    # ----------------------------------------------------------------------
    # BACKEND CONTROL (with progress bar)
    # ----------------------------------------------------------------------

    def _start_backend(self):
        self.backend_progress["value"] = 0
        self.backend_progress.update()

        if not os.path.exists(self.app.paths.backend_main):
            messagebox.showwarning("Backend Missing",
                                   "Backend main.py not found.")
            append_log(self.app.paths, "Backend main.py missing.")
            return

        try:
            for i in range(0, 61, 15):
                self.backend_progress["value"] = i
                self.backend_progress.update()
                time.sleep(0.05)

            # Attempt to start backend and wait for /health
            ok, report = attempt_backend_restart(self.app.paths, timeout=10)
            if ok:
                self.backend_progress["value"] = 100
                append_log(self.app.paths, "Backend started and healthy via GUI.")
                append_audit(self.app.paths, "Backend started via GUI.")
                messagebox.showinfo("Backend", "Backend started and healthy.")
            else:
                append_log(self.app.paths, "Backend start requested via GUI but health check failed.")
                append_audit(self.app.paths, "Backend start requested (health failed).")
                # Create a repair suggestion so operator can review detailed diagnostics
                sid = create_suggestion(
                    self.app.paths,
                    "repair_backend",
                    "Automatic backend start attempted but service did not become healthy.",
                    {"report": report},
                    owner_required=True,
                )
                messagebox.showwarning("Backend", "Start attempted but backend failed health check. A repair suggestion was created for review.")

        except Exception as e:
            append_log(self.app.paths, f"Backend start failed: {e}")
            append_audit(self.app.paths, f"Backend start failed: {e}")
            messagebox.showerror("Backend Error", str(e))

    def _stop_backend(self):
        self.backend_progress["value"] = 0
        self.backend_progress.update()

        # Placeholder for actual stop logic
        for i in range(0, 101, 20):
            self.backend_progress["value"] = i
            self.backend_progress.update()
            time.sleep(0.1)

        append_log(self.app.paths, "Backend stop requested (placeholder).")
        append_audit(self.app.paths, "Backend stop requested (placeholder).")
        messagebox.showinfo("Backend", "Stop backend not implemented yet.")

    def _restart_backend(self):
        self._stop_backend()
        time.sleep(0.5)
        self._start_backend()

    def _open_dashboard(self):
        if not os.path.exists(self.app.paths.dashboard_index):
            messagebox.showwarning("Dashboard Missing",
                                   "Dashboard index.html not found.")
            append_log(self.app.paths, "Dashboard index missing.")
            return

        import webbrowser
        url = f"file:///{self.app.paths.dashboard_index.replace(os.sep, '/')}"
        webbrowser.open(url)
        append_log(self.app.paths, "Dashboard opened via GUI.")
        append_audit(self.app.paths, "Dashboard opened via GUI.")

        # ============================================================================
# ALWAYS LISTENING PAGE
# ============================================================================

class ListeningPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Always Listening",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "IntentOS can listen for a wake-word locally.\n"
                "This requires explicit Owner consent.\n"
                "No audio is ever sent externally unless a feature explicitly requires it."
            ),
            style="Muted.TLabel",
            wraplength=600,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # Consent toggle
        self.consent_var = tk.BooleanVar(value=self.app.listening_state.consent_given)
        consent_chk = ttk.Checkbutton(
            card,
            text="I grant consent for local wake-word detection",
            variable=self.consent_var,
            command=self._toggle_consent,
        )
        consent_chk.pack(anchor="w", padx=12, pady=(4, 4))

        # Enabled toggle
        self.enabled_var = tk.BooleanVar(value=self.app.listening_state.enabled)
        enabled_chk = ttk.Checkbutton(
            card,
            text="Enable Always Listening",
            variable=self.enabled_var,
            command=self._toggle_enabled,
        )
        enabled_chk.pack(anchor="w", padx=12, pady=(4, 12))

        # One-click controls: Test and Pause
        btn_row = ttk.Frame(card)
        btn_row.pack(fill="x", padx=12, pady=(4, 8))
        ttk.Button(btn_row, text="Test Microphone", style="Subtle.TButton", command=lambda: (self.app._test_microphone(), None)).pack(side="left")
        ttk.Button(btn_row, text="Pause 5 min", style="Subtle.TButton", command=lambda: (self.app._pause_listening(5), messagebox.showinfo("Paused", "Listening paused for 5 minutes."))).pack(side="left", padx=(8,0))
        ttk.Button(btn_row, text="Troubleshoot Microphone", style="Subtle.TButton", command=lambda: self.app._open_os_microphone_settings()).pack(side="right")

        ttk.Label(
            card,
            text="Changes take effect immediately.",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=12, pady=(0, 12))

    def _toggle_consent(self):
        self.app.listening_state.consent_given = self.consent_var.get()
        save_listening_state(self.app.paths, self.app.listening_state)
        append_log(self.app.paths, f"Listening consent set to {self.consent_var.get()}")


class PrivacyDashboardPage(BasePage):
    """Privacy dashboard: shows consents, telemetry status, listening controls and telemetry viewer."""
    def __init__(self, master, app):
        super().__init__(master, app)
        self.grid_columnconfigure(0, weight=1)
        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Privacy Dashboard", font=("Segoe UI Semibold", 16)).pack(anchor="w", pady=(10, 4), padx=12)

        ttk.Label(card, text="Overview of privacy settings, local telemetry and active listening.", style="Muted.TLabel").pack(anchor="w", padx=12)

        # Consent summary frame
        summary = ttk.Frame(card)
        summary.pack(fill="x", padx=12, pady=(8, 8))

        self.microphone_label = ttk.Label(summary, text="Microphone: unknown", style="Muted.TLabel")
        self.microphone_label.pack(anchor="w")
        self.location_label = ttk.Label(summary, text="Location: unknown", style="Muted.TLabel")
        self.location_label.pack(anchor="w")
        self.telemetry_label = ttk.Label(summary, text="Telemetry: unknown", style="Muted.TLabel")
        self.telemetry_label.pack(anchor="w")

        # Listening control
        ctrl = ttk.Frame(card)
        ctrl.pack(fill="x", padx=12, pady=(0, 8))
        self.listen_status = ttk.Label(ctrl, text="Listening: unknown", style="Muted.TLabel")
        self.listen_status.pack(side="left")
        ttk.Button(ctrl, text="Toggle Listening", style="Accent.TButton", command=self._toggle_listening).pack(side="right")

        # Telemetry viewer
        viewer_card = ttk.Frame(self, style="Card.TFrame")
        viewer_card.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 8))
        _label_card(viewer_card, "Telemetry (local)", font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(10, 4), padx=12)
        self.telemetry_view = scrolledtext.ScrolledText(viewer_card, wrap="word", height=10)
        self.telemetry_view.pack(fill="both", expand=True, padx=12, pady=(4, 8))

        # Telemetry actions
        actions = ttk.Frame(viewer_card)
        actions.pack(fill="x", padx=12, pady=(0, 12))
        ttk.Button(actions, text="Refresh", style="Subtle.TButton", command=self._refresh).pack(side="right")
        ttk.Button(actions, text="Clear Local Telemetry", style="Subtle.TButton", command=self._clear_telemetry).pack(side="right", padx=(8,0))

        self._refresh()

    def _refresh(self):
        try:
            mic = get_feature_consent(self.app.paths, "microphone")
            loc = get_feature_consent(self.app.paths, "location")
            tel = get_feature_consent(self.app.paths, "telemetry")
            self.microphone_label.config(text=f"Microphone consent: {mic}")
            self.location_label.config(text=f"Location consent: {loc}")
            self.telemetry_label.config(text=f"Telemetry consent: {tel}")

            ls = load_listening_state(self.app.paths)
            self.listen_status.config(text=f"Listening: {'enabled' if ls.enabled else 'disabled'}")

            # show telemetry events
            evs = load_telemetry_events(self.app.paths)
            self.telemetry_view.delete("1.0", tk.END)
            if not evs:
                self.telemetry_view.insert(tk.END, "No local telemetry recorded.\n")
            else:
                self.telemetry_view.insert(tk.END, json.dumps(evs[-200:], ensure_ascii=False, indent=2))

            # show keyword counts if listener exists
            kc = {}
            try:
                if getattr(self.app, "microphone_listener", None):
                    kc = getattr(self.app.microphone_listener, "keyword_counts", {}) or {}
            except Exception:
                kc = {}
            self.telemetry_view.insert(tk.END, "\n\nKeyword counts:\n")
            self.telemetry_view.insert(tk.END, json.dumps(kc, ensure_ascii=False, indent=2))
        except Exception as e:
            append_log(self.app.paths, f"Failed to refresh privacy dashboard: {e}")

    def _toggle_listening(self):
        try:
            ls = load_listening_state(self.app.paths)
            self.app._set_listening_enabled(not ls.enabled)
            self._refresh()
        except Exception as e:
            append_log(self.app.paths, f"Failed toggle listening from privacy dashboard: {e}")

    def _clear_telemetry(self):
        try:
            ok = clear_telemetry(self.app.paths)
            if ok:
                messagebox.showinfo("Cleared", "Local telemetry cleared.")
            else:
                messagebox.showerror("Failed", "Could not clear telemetry; check logs.")
            self._refresh()
        except Exception as e:
            append_log(self.app.paths, f"Failed to clear telemetry: {e}")
    # ============================================================================
# SUBSYSTEM AUTO-REPAIR HELPERS (ROBUST REPLACEMENT SCRIPTS)
# ============================================================================

def create_default_backend_main(paths: IntentOSPaths) -> None:
    """
    Create a robust default backend/main.py if missing.
    Implements a minimal FastAPI app with /health endpoint.
    """
    try:
        os.makedirs(paths.backend_dir, exist_ok=True)
        if os.path.exists(paths.backend_main):
            return

        content = """\
import uvicorn
from fastapi import FastAPI

app = FastAPI(title="IntentOS Backend (Default)")

@app.get("/health")
def health():
    return {"status": "ok", "backend": "default"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
"""
        with open(paths.backend_main, "w", encoding="utf-8") as f:
            f.write(content)
        append_log(paths, "Created default backend/main.py.")
        append_audit(paths, "Default backend main.py created.")
    except Exception as e:
        append_log(paths, f"Failed to create default backend main.py: {e}")


def create_default_cli_script(paths: IntentOSPaths) -> None:
    """
    Create a robust default cli/cli.py if missing.
    Implements a minimal, safe CLI with --status and intent echo.
    """
    try:
        os.makedirs(paths.cli_dir, exist_ok=True)
        if os.path.exists(paths.cli_script):
            return

        content = """\
#!/usr/bin/env python
import sys

def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--status":
        print("IntentOS CLI default: status OK")
        return

    if len(sys.argv) >= 2:
        intent = sys.argv[1]
        print(f"IntentOS CLI default: received intent '{intent}'")
        return

    print("IntentOS CLI default. Usage:")
    print("  cli.py --status")
    print("  cli.py <intent-name>")

if __name__ == "__main__":
    main()
"""
        with open(paths.cli_script, "w", encoding="utf-8") as f:
            f.write(content)
        try:
            os.chmod(paths.cli_script, 0o755)
        except Exception:
            pass
        append_log(paths, "Created default cli/cli.py.")
        append_audit(paths, "Default CLI script created.")
    except Exception as e:
        append_log(paths, f"Failed to create default CLI script: {e}")


def create_default_dashboard_index(paths: IntentOSPaths) -> None:
    """
    Create a robust default dashboard/index.html if missing.
    Implements a minimal, static HTML shell.
    """
    try:
        os.makedirs(paths.dashboard_dir, exist_ok=True)
        if os.path.exists(paths.dashboard_index):
            return

        content = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>IntentOS Dashboard (Default)</title>
  <style>
    body {
      background: #020617;
      color: #e5e7eb;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      padding: 2rem;
    }
    .card {
      background: #020617;
      border-radius: 0.75rem;
      border: 1px solid #1f2937;
      padding: 1.5rem;
      max-width: 640px;
    }
    h1 {
      color: #38bdf8;
    }
    .muted {
      color: #9ca3af;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>IntentOS Dashboard (Default)</h1>
    <p class="muted">
      This is the default dashboard shell generated by the IntentOS Owner Console.
      You can replace this file with a custom dashboard implementation at:
    </p>
    <pre>dashboard/index.html</pre>
  </div>
</body>
</html>
"""
        with open(paths.dashboard_index, "w", encoding="utf-8") as f:
            f.write(content)
        append_log(paths, "Created default dashboard/index.html.")
        append_audit(paths, "Default dashboard index.html created.")
    except Exception as e:
        append_log(paths, f"Failed to create default dashboard index.html: {e}")


def create_default_root_file(paths: IntentOSPaths) -> None:
    """
    Create a minimal default root file if missing.
    """
    try:
        if os.path.exists(paths.root_file):
            return
        content = "# IntentOS default root engine placeholder.\n"
        with open(paths.root_file, "w", encoding="utf-8") as f:
            f.write(content)
        append_log(paths, "Created default root engine file.")
        append_audit(paths, "Default root engine file created.")
    except Exception as e:
        append_log(paths, f"Failed to create default root file: {e}")

# ============================================================================
# SUBSYSTEM MANAGER PAGE (with auto-repair capability)
# ============================================================================

class SubsystemManagerPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, columnspan=2, sticky="nsew",
                  padx=0, pady=(0, 8))

        _label_card(card, "Subsystem Manager",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "Manage IntentOS subsystems.\n"
                "This includes backend, dashboard, CLI, plugins, and engine components.\n"
                "Missing core files can be auto-repaired with robust defaults."
            ),
            style="Muted.TLabel",
            wraplength=800,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # Subsystem list
        self.tree = ttk.Treeview(
            card,
            columns=("status", "path"),
            show="headings",
            height=10,
        )
        self.tree.heading("status", text="Status")
        self.tree.heading("path", text="Path")
        self.tree.column("status", width=120)
        self.tree.column("path", width=600)

        self.tree.pack(fill="both", expand=True, padx=12, pady=(4, 8))

        # Actions
        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(fill="x", padx=12, pady=(0, 12))

        ttk.Button(
            actions,
            text="Refresh",
            style="Subtle.TButton",
            command=self._refresh_subsystems,
        ).pack(side="left")

        ttk.Button(
            actions,
            text="Repair Missing Core Subsystems",
            style="Accent.TButton",
            command=self._repair_missing_subsystems,
        ).pack(side="right")

        self._refresh_subsystems()

    def _refresh_subsystems(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        subsystems = [
            ("Root Engine", self.app.paths.root_file),
            ("Backend main.py", self.app.paths.backend_main),
            ("Dashboard index.html", self.app.paths.dashboard_index),
            ("CLI script", self.app.paths.cli_script),
            ("Permissions", self.app.paths.permissions_file),
            ("Owner Config", self.app.paths.owner_file),
            ("Listening Config", self.app.paths.listening_file),
            ("Maintenance Config", self.app.paths.maintenance_file),
        ]

        for name, path in subsystems:
            exists = os.path.exists(path)
            status = "OK" if exists else "Missing"
            self.tree.insert("", "end", values=(status, path))

    def _repair_missing_subsystems(self):
        """
        Scan core subsystems and auto-generate robust replacements for missing files.
        Never overwrites existing files.
        """
        repairs = []

        # Root engine
        if not os.path.exists(self.app.paths.root_file):
            create_default_root_file(self.app.paths)
            repairs.append("Root engine")

        # Backend
        if not os.path.exists(self.app.paths.backend_main):
            create_default_backend_main(self.app.paths)
            repairs.append("Backend main.py")

        # Dashboard
        if not os.path.exists(self.app.paths.dashboard_index):
            create_default_dashboard_index(self.app.paths)
            repairs.append("Dashboard index.html")

        # CLI
        if not os.path.exists(self.app.paths.cli_script):
            create_default_cli_script(self.app.paths)
            repairs.append("CLI script")

        # Configs
        if not os.path.exists(self.app.paths.permissions_file):
            save_permissions(self.app.paths, load_permissions(self.app.paths))
            repairs.append("permissions.json")

        if not os.path.exists(self.app.paths.listening_file):
            save_listening_state(self.app.paths, load_listening_state(self.app.paths))
            repairs.append("listening.json")

        if not os.path.exists(self.app.paths.maintenance_file):
            save_maintenance_state(self.app.paths, load_maintenance_state(self.app.paths))
            repairs.append("maintenance.json")

        if repairs:
            msg = "Repaired components:\n- " + "\n- ".join(repairs)
            append_log(self.app.paths, f"Subsystem auto-repair executed: {', '.join(repairs)}")
            append_audit(self.app.paths, f"Subsystem auto-repair executed: {', '.join(repairs)}")
            messagebox.showinfo("Subsystem Repair", msg)
        else:
            messagebox.showinfo("Subsystem Repair", "No missing core subsystems detected.")

        self._refresh_subsystems()

# ============================================================================
# CONFIG EDITOR PAGE (resilient, self-healing configs)
# ============================================================================

class ConfigEditorPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Config Editor",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "Edit configuration files directly from the Owner Console.\n"
                "If a config file is missing or corrupted, a safe default is recreated.\n"
                "Changes may require a console restart to take effect."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # File selector
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", padx=12, pady=(4, 4))

        ttk.Label(row, text="Select config file:").pack(side="left")

        self.file_var = tk.StringVar()
        files = [
            self.app.paths.permissions_file,
            self.app.paths.owner_file,
            self.app.paths.listening_file,
            self.app.paths.maintenance_file,
        ]
        self.file_menu = ttk.Combobox(
            row,
            textvariable=self.file_var,
            values=files,
            state="readonly",
            width=80,
        )
        self.file_menu.pack(side="left", padx=(8, 0))
        self.file_menu.bind("<<ComboboxSelected>>", self._load_file)

        # Editor box
        self.editor = scrolledtext.ScrolledText(
            self,
            wrap="word",
            bg="#020617",
            fg=IntentOSTheme.TEXT_PRIMARY,
            insertbackground=IntentOSTheme.TEXT_PRIMARY,
        )
        self.editor.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 8))

        # Save button
        ttk.Button(
            self,
            text="Save Changes",
            style="Accent.TButton",
            command=self._save_file,
        ).grid(row=2, column=0, sticky="e", padx=0, pady=(0, 12))

    def _load_file(self, *_):
        path = self.file_var.get()
        if not path:
            return

        # Self-healing: if missing and known config, recreate default
        if not os.path.exists(path):
            if path == self.app.paths.permissions_file:
                save_permissions(self.app.paths, load_permissions(self.app.paths))
            elif path == self.app.paths.listening_file:
                save_listening_state(self.app.paths, load_listening_state(self.app.paths))
            elif path == self.app.paths.maintenance_file:
                save_maintenance_state(self.app.paths, load_maintenance_state(self.app.paths))
            elif path == self.app.paths.owner_file:
                # Owner config is optional; create an empty stub
                save_owner(self.app.paths, OwnerInfo(name="", passphrase=""))
            append_log(self.app.paths, f"Config {path} recreated during load.")
            append_audit(self.app.paths, f"Config {path} recreated during load.")

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.editor.delete("1.0", tk.END)
            self.editor.insert(tk.END, content)
        except Exception as e:
            append_log(self.app.paths, f"Failed to load config {path}: {e}")
            messagebox.showerror("Load Error", str(e))

    def _save_file(self):
        path = self.file_var.get()
        if not path:
            return

        content = self.editor.get("1.0", tk.END)

        try:
            # Backup before write
            backup_file(path, self.app.paths)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

            append_log(self.app.paths, f"Config updated: {path}")
            append_audit(self.app.paths, f"Config updated: {path}")

            messagebox.showinfo(
                "Config Saved",
                "Changes saved.\nRestart the console for changes to take effect."
            )
        except Exception as e:
            append_log(self.app.paths, f"Failed to save config {path}: {e}")
            messagebox.showerror("Save Error", str(e))

# ============================================================================
# INTENT RUNNER PAGE (resilient, can auto-create CLI)
# ============================================================================

class IntentRunnerPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Intent Runner",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "Run intents directly through the CLI.\n"
                "If the CLI script is missing, a robust default will be generated."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # Intent input
        ttk.Label(card, text="Intent name:").pack(anchor="w", padx=12)
        self.intent_var = tk.StringVar()
        ttk.Entry(card, textvariable=self.intent_var).pack(
            anchor="w", padx=12, pady=(0, 8), fill="x"
        )

        ttk.Button(
            card,
            text="Run Intent",
            style="Accent.TButton",
            command=self._run_intent,
        ).pack(anchor="w", padx=12, pady=(0, 12))

        # Output
        self.output = scrolledtext.ScrolledText(
            self,
            wrap="word",
            height=16,
            bg="#020617",
            fg=IntentOSTheme.TEXT_PRIMARY,
            insertbackground=IntentOSTheme.TEXT_PRIMARY,
        )
        self.output.grid(row=2, column=0, sticky="nsew", padx=0, pady=(0, 8))

    def _run_intent(self):
        self.output.delete("1.0", tk.END)
        name = self.intent_var.get().strip()

        if not name:
            self.output.insert(tk.END, "Please enter an intent name.\n")
            return

        if not os.path.exists(self.app.paths.cli_script):
            create_default_cli_script(self.app.paths)
            self.output.insert(
                tk.END,
                "CLI script was missing and has been recreated with a default implementation.\n"
            )

        proc = run_subprocess(
            [sys.executable, os.path.basename(self.app.paths.cli_script), name],
            cwd=os.path.dirname(self.app.paths.cli_script),
        )

        if proc.stdout:
            self.output.insert(tk.END, proc.stdout)
        if proc.stderr:
            self.output.insert(tk.END, "\n[stderr]\n" + proc.stderr)

        append_log(self.app.paths, f"Intent run via GUI: {name}")
        append_audit(self.app.paths, f"Intent run: {name}")

# ============================================================================
# LOGS VIEWER PAGE (resilient, self-healing logs)
# ============================================================================

class LogsPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Logs & Activity",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text="View system logs, audit logs, and sharing logs.",
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # File selector
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", padx=12, pady=(4, 4))

        ttk.Label(row, text="Select log file:").pack(side="left")

        self.log_var = tk.StringVar()
        logs = [
            self.app.paths.log_file,
            self.app.paths.audit_log_file,
            self.app.paths.sharing_log_file,
        ]
        self.log_menu = ttk.Combobox(
            row,
            textvariable=self.log_var,
            values=logs,
            state="readonly",
            width=80,
        )
        self.log_menu.pack(side="left", padx=(8, 0))
        self.log_menu.bind("<<ComboboxSelected>>", self._load_log)

        # Log viewer
        self.viewer = scrolledtext.ScrolledText(
            self,
            wrap="word",
            bg="#020617",
            fg=IntentOSTheme.TEXT_PRIMARY,
            insertbackground=IntentOSTheme.TEXT_PRIMARY,
        )
        self.viewer.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 8))

    def _load_log(self, *_):
        path = self.log_var.get()
        if not path:
            return

        # Self-healing: create empty log if missing
        if not os.path.exists(path):
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write("")
                append_log(self.app.paths, f"Log file created: {path}")
            except Exception as e:
                append_log(self.app.paths, f"Failed to create log {path}: {e}")
                messagebox.showerror("Log Error", f"Failed to create log file:\n{path}")
                return

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.viewer.delete("1.0", tk.END)
            self.viewer.insert(tk.END, content)
        except Exception as e:
            append_log(self.app.paths, f"Failed to read log {path}: {e}")
            messagebox.showerror("Load Error", str(e))

# ============================================================================
# DATA SHARING INSPECTOR PAGE (resilient, self-healing log)
# ============================================================================

class DataSharingPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Data Sharing Inspector",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "This panel shows all data-sharing events recorded by IntentOS.\n"
                "Every event includes timestamp, subsystem, and payload summary.\n"
                "If the sharing log is missing, it will be created automatically."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        # Viewer
        self.viewer = scrolledtext.ScrolledText(
            self,
            wrap="word",
            bg="#020617",
            fg=IntentOSTheme.TEXT_PRIMARY,
            insertbackground=IntentOSTheme.TEXT_PRIMARY,
        )
        self.viewer.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 8))

        ttk.Button(
            self,
            text="Refresh",
            style="Subtle.TButton",
            command=self._refresh,
        ).grid(row=2, column=0, sticky="e", padx=0, pady=(0, 12))

        self._refresh()

    def _refresh(self):
        self.viewer.delete("1.0", tk.END)

        path = self.app.paths.sharing_log_file
        # Self-healing: create empty sharing log if missing
        if not os.path.exists(path):
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write("")
                append_log(self.app.paths, "Created empty sharing.log.")
            except Exception as e:
                append_log(self.app.paths, f"Failed to create sharing log: {e}")
                self.viewer.insert(tk.END, f"Error creating sharing log:\n{e}\n")
                return

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        ts = event.get("ts", "unknown")
                        subsystem = event.get("subsystem", "unknown")
                        payload = event.get("payload", {})
                        self.viewer.insert(
                            tk.END,
                            f"[{ts}] subsystem={subsystem}\n"
                            f"  payload: {json.dumps(payload, indent=2)}\n\n"
                        )
                    except Exception:
                        continue
        except Exception as e:
            append_log(self.app.paths, f"Error reading sharing log: {e}")
            self.viewer.insert(tk.END, f"Error reading sharing log:\n{e}\n")

# ============================================================================
# SIMPLE RETRY HELPER (FOR IO-BOUND OPS)
# ============================================================================

def retry_operation(op, description: str, paths: IntentOSPaths, retries: int = 3, delay: float = 0.3):
    """
    Run an operation with simple retry logic.
    - op: callable with no args
    - description: human readable string for logging
    Returns (success: bool, result: Any | None)
    """
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            result = op()
            if attempt > 1:
                append_log(paths, f"{description} succeeded on attempt {attempt}.")
            return True, result
        except Exception as e:
            last_exc = e
            append_log(paths, f"{description} failed on attempt {attempt}: {e}")
            time.sleep(delay)
    append_log(paths, f"{description} permanently failed after {retries} attempts: {last_exc}")
    return False, None


# ============================================================================
# PERMISSIONS MANAGER PAGE (with resilient toggling)
# ============================================================================

class PermissionsPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Permissions Manager",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "Manage feature-level permissions.\n"
                "Some features require explicit Owner consent.\n"
                "Changes are persisted to permissions.json with retries and logging."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        self.tree = ttk.Treeview(
            card,
            columns=("description", "enabled"),
            show="headings",
            height=10,
        )
        self.tree.heading("description", text="Description")
        self.tree.heading("enabled", text="Enabled")
        self.tree.column("description", width=500)
        self.tree.column("enabled", width=120)

        self.tree.pack(fill="both", expand=True, padx=12, pady=(4, 8))

        # Provide a scrolling detail area for reports
        self.detail_view = scrolledtext.ScrolledText(self, wrap="word", height=12)
        self.detail_view.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.grid_rowconfigure(1, weight=1)

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(fill="x", padx=12, pady=(0, 12))

        self.status_label = ttk.Label(
            actions,
            text="",
            style="Muted.TLabel",
        )
        self.status_label.pack(side="left")

        self.toggle_btn = ttk.Button(
            actions,
            text="Toggle Selected",
            style="Accent.TButton",
            command=self._toggle_selected,
        )
        self.toggle_btn.pack(side="right")

        ttk.Button(
            actions,
            text="Manage Consents",
            style="Subtle.TButton",
            command=self._manage_consents,
        ).pack(side="right", padx=(8,0))
        features = self.app.permissions.get("features", {})
        if not isinstance(features, dict):
            self.app.permissions["features"] = {}
            features = self.app.permissions["features"]

        for key, info in features.items():
            desc = info.get("description", "")
            enabled = info.get("enabled", False)
            self.tree.insert("", "end", iid=key, values=(desc, enabled))

    def _toggle_selected(self):
        sel = self.tree.selection()
        if not sel:
            self.status_label.config(text="No feature selected.")
            return

        key = sel[0]
        feature = self.app.permissions["features"].get(key)
        if not feature:
            self.status_label.config(text="Invalid selection.")
            return

        # If enabling a feature that requires consent but consent not given, prompt to manage consents
        if not feature.get("enabled", False) and feature.get("requires_consent") and not feature.get("consent_given", False):
            if messagebox.askyesno("Consent required", f"The feature '{key}' requires explicit consent. Open consent manager now?"):
                self._manage_consents()
                return

        # If feature is owner-protected (owner_required True), require owner
        if feature.get("owner_required") and not self.app.owner:
            messagebox.showerror(
                "Owner Required",
                "Only the Owner (with passphrase) can enable or disable this feature."
            )
            return

        # Visual feedback: disable button during operation
        self.toggle_btn.state(["disabled"])
        self.status_label.config(text="Toggling permission...")

        try:
            feature["enabled"] = not feature.get("enabled", False)

            def _save():
                save_permissions(self.app.paths, self.app.permissions)

            ok, _ = retry_operation(_save, f"Saving permissions after toggle {key}", self.app.paths)
            if not ok:
                messagebox.showerror(
                    "Permissions Error",
                    "Failed to save permissions after multiple attempts. See logs for details."
                )
            else:
                append_log(self.app.paths, f"Permission toggled: {key}")
                append_audit(self.app.paths, f"Permission toggled: {key}")
                self.status_label.config(text=f"Toggled '{key}' to {feature['enabled']}.")
        finally:
            self.toggle_btn.state(["!disabled"])
            self._refresh()
        
    def _manage_consents(self):
        """Open a modal dialog to manage per-feature consents."""
        top = tk.Toplevel(self)
        top.title("Manage Consents")
        top.transient(self)
        top.grab_set()

        card = ttk.Frame(top, padding=12)
        card.pack(fill="both", expand=True)

        ttk.Label(
            card,
            text=(
                "Manage feature consents. Toggle consent for features that require it.\n"
                "Owner-protected consents will prompt for the Owner passphrase."
            ),
            style="Muted.TLabel",
            wraplength=600,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        var_map = {}
        features = self.app.permissions.get("features", {})
        for key, info in features.items():
            # Only show features that explicitly require consent - others don't need consent management
            if not info.get("requires_consent"):
                continue
            var = tk.BooleanVar(value=bool(info.get("consent_given", False)))
            cb = ttk.Checkbutton(card, text=f"{key} - {info.get('description','')}", variable=var)
            cb.pack(anchor="w", padx=6, pady=2)
            # Special explanatory note for microphone consent
            try:
                if key == "microphone":
                    ttk.Label(card, text="Note: consenting to the microphone will cause the app to listen by default; you can later disable listening.", style="Muted.TLabel", wraplength=640).pack(anchor="w", padx=16, pady=(0,6))
            except Exception as e:
                append_log(self.app.paths, f"Failed to add microphone note: {e}")
            var_map[key] = (var, bool(info.get("owner_required", False)))

        btn_frame = ttk.Frame(card)
        btn_frame.pack(fill="x", pady=(8, 0))

        def _save():
            owner_pass = None
            # If any owner-protected consent is being enabled and Owner is not currently present, prompt once
            needs_owner = any(owner and var.get() for var, owner in var_map.values())
            if needs_owner and not self.app.owner:
                owner_pass = simpledialog.askstring(
                    "Owner passphrase",
                    "Enter Owner passphrase to allow changing owner-protected consents:",
                    show="*",
                )
                if owner_pass is None:
                    return

            errors = []
            for key, (var, owner_req) in var_map.items():
                desired = bool(var.get())
                ok = set_feature_consent(self.app.paths, key, desired, owner_passphrase=owner_pass)
                if not ok:
                    errors.append(key)

            if errors:
                messagebox.showerror("Save Failed", f"Could not set consent for: {', '.join(errors)}")
                return

            # If microphone consent changed, apply listening state accordingly
            try:
                for key, (var, owner_req) in var_map.items():
                    if key == "microphone":
                        try:
                            if bool(var.get()):
                                self.app._set_listening_enabled(True)
                            else:
                                self.app._set_listening_enabled(False)
                        except Exception as e:
                            append_log(self.app.paths, f"Failed to apply listening state after consent change: {e}")
            except Exception as e:
                append_log(self.app.paths, f"Unexpected error while applying consent side effects: {e}")

            append_log(self.app.paths, f"Consents updated: {', '.join([k for k,(v,o) in var_map.items() if v.get()])}")
            append_audit(self.app.paths, "Consents updated via UI")
            self._refresh()
            top.destroy()

        ttk.Button(btn_frame, text="Save", style="Accent.TButton", command=_save).pack(side="right", padx=(8, 0))
        ttk.Button(btn_frame, text="Cancel", style="Subtle.TButton", command=top.destroy).pack(side="right")
        
# ============================================================================
# SUGGESTIONS PAGE (AI recommendations)
# ============================================================================

class SuggestionsPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "AI Suggestions",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "AI-generated suggestions that can be reviewed by a human operator and executed upon approval.\n"
                "Suggestions are saved to suggestions.json and changes are audited."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        self.tree = ttk.Treeview(
            card,
            columns=("message", "ts", "state"),
            show="headings",
            height=10,
        )
        self.tree.heading("message", text="Suggestion")
        self.tree.heading("ts", text="Created")
        self.tree.heading("state", text="State")
        self.tree.column("message", width=500)
        self.tree.column("ts", width=140)
        self.tree.column("state", width=120)
        self.tree.pack(fill="both", expand=True, padx=12, pady=(4, 8))

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(fill="x", padx=12, pady=(0, 12))

        self.status_label = ttk.Label(
            actions,
            text="",
            style="Muted.TLabel",
        )
        self.status_label.pack(side="left")

        btns = ttk.Frame(actions)
        btns.pack(side="right")

        self.approve_btn = ttk.Button(btns, text="Approve & Execute", style="Accent.TButton", command=self._approve_selected)
        self.approve_btn.pack(side="right", padx=(8,0))

        self.auto_btn = ttk.Button(btns, text="Autonomously Repair", style="Accent.TButton", command=self._autonomous_repair)
        self.auto_btn.pack(side="right", padx=(8,0))

        ttk.Button(btns, text="Undo", style="Subtle.TButton", command=self._undo_selected).pack(side="right", padx=(0,8))
        ttk.Button(btns, text="Reject", style="Subtle.TButton", command=self._reject_selected).pack(side="right")

        ttk.Button(actions, text="Refresh", style="Subtle.TButton", command=self._refresh).pack(side="right", padx=(8,0))

        self._refresh()

    def _refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for s in list_suggestions(self.app.paths):
            msg = s.get("message", "")
            ts = s.get("ts", "")
            state = s.get("state", "")
            self.tree.insert("", "end", iid=s.get("id"), values=(msg, ts, state))
        self.status_label.config(text=f"{len(self.tree.get_children())} suggestions")
        self.detail_view.delete("1.0", tk.END)

    def _get_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Please select a suggestion first.")
            return None
        return sel[0]

    def _show_selected_details(self):
        sid = self._get_selected()
        if not sid:
            return
        s = next((x for x in list_suggestions(self.app.paths) if x.get("id") == sid), None)
        if not s:
            return
        self.detail_view.delete("1.0", tk.END)
        payload = s.get("payload") or {}
        report = payload.get("report") or s.get("report") or ""
        text = f"ID: {s.get('id')}\nCreated: {s.get('ts')}\nState: {s.get('state')}\nOwner protected: {s.get('owner_required')}\n\nMessage:\n{s.get('message')}\n\n"
        if payload:
            try:
                text += "Payload:\n" + json.dumps(payload, ensure_ascii=False, indent=2) + "\n\n"
            except Exception:
                text += f"Payload: {payload}\n\n"
        if report:
            text += "Report:\n" + (report if isinstance(report, str) else json.dumps(report, ensure_ascii=False, indent=2)) + "\n"
        self.detail_view.insert(tk.END, text)

    def _autonomous_repair(self):
        sid = self._get_selected()
        if not sid:
            return
        s = next((x for x in list_suggestions(self.app.paths) if x.get("id") == sid), None)
        if not s:
            messagebox.showerror("Not found", "Suggestion not found.")
            return
        # Show plan preview when available
        plan = (s.get("payload") or {}).get("plan")
        if plan:
            if messagebox.askyesno("Review Repair Plan", "A repair plan is available. Review it before autonomous execution?"):
                self._show_plan_modal(sid, s, allow_execute=True)
                return

        if s.get("owner_required") and not self.app.owner:
            pwd = simpledialog.askstring("Owner passphrase", "Enter Owner passphrase to allow autonomous repair:", show="*")
            if pwd is None:
                return
            ok = approve_suggestion(self.app.paths, sid, operator=self.app.username or "operator", owner_passphrase=pwd)
        else:
            if not messagebox.askyesno("Autonomous Repair", f"Execute autonomous repair now?\n\n{s.get('message')}"):
                return
            ok = approve_suggestion(self.app.paths, sid, operator=self.app.username or "operator")

        if ok:
            messagebox.showinfo("Repair", "Autonomous repair executed (see audit/logs).")
        else:
            messagebox.showerror("Repair Failed", "Autonomous repair failed; check logs.")
        self._refresh()

    def _approve_selected(self):
        sid = self._get_selected()
        if not sid:
            return
        s = next((x for x in list_suggestions(self.app.paths) if x.get("id") == sid), None)
        if not s:
            messagebox.showerror("Not found", "Suggestion not found.")
            return
        # If there's a plan attached, offer preview before immediate approval
        plan = (s.get("payload") or {}).get("plan")
        if plan:
            if not messagebox.askyesno("Preview Repair Plan", f"A repair plan has been generated. Would you like to preview the plan before executing?"):
                # if operator doesn't want preview, continue to confirm execution
                pass
            else:
                # show plan modal
                self._show_plan_modal(sid, s)
                return

        if s.get("owner_required") and not self.app.owner:
            pwd = simpledialog.askstring("Owner passphrase", "Enter Owner passphrase to approve this suggestion:", show="*")
            if pwd is None:
                return
            ok = approve_suggestion(self.app.paths, sid, operator=self.app.username or "operator", owner_passphrase=pwd)
        else:
            if not messagebox.askyesno("Confirm", f"Approve and execute suggestion?\n\n{s.get('message')}"):
                return
            ok = approve_suggestion(self.app.paths, sid, operator=self.app.username or "operator")

        if ok:
            messagebox.showinfo("Executed", "Suggestion approved and executed.")
        else:
            messagebox.showerror("Failed", "Failed to approve or execute suggestion; check logs.")
        self._refresh()

    def _reject_selected(self):
        sid = self._get_selected()
        if not sid:
            return
        if not messagebox.askyesno("Confirm Reject", "Reject this suggestion? This cannot be undone."):
            return
        set_suggestion_state(self.app.paths, sid, "rejected", operator=self.app.username or "operator")
        append_log(self.app.paths, f"Suggestion {sid} rejected by {self.app.username or 'operator'}")
        self._refresh()

    def _undo_selected(self):
        sid = self._get_selected()
        if not sid:
            return
        # find undo entries for this suggestion
        entries = [e for e in list_undo_entries(self.app.paths) if e.get("sid") == sid]
        if not entries:
            messagebox.showinfo("No undo entries", "No undo entries found for this suggestion.")
            return
        # pick the most recent
        entry = entries[-1]
        summary = json.dumps(entry, ensure_ascii=False)
        if not messagebox.askyesno("Confirm Undo", f"Perform undo action for suggestion {sid}?\n\n{summary}"):
            return
        ok, msg = perform_undo_action(self.app.paths, entry)
        if ok:
            messagebox.showinfo("Undo performed", msg)
            append_audit(self.app.paths, f"Undo for suggestion {sid} performed: {msg}")
        else:
            messagebox.showerror("Undo failed", msg)
        self._refresh()


# ============================================================================
# PLUGIN MANAGER PAGE (with retry + visual feedback)
# ============================================================================

class PluginManagerPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Plugin Manager",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "Manage installed plugins and inspect their manifests.\n"
                "If plugin folders are missing, this view will recover gracefully."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        self.tree = ttk.Treeview(
            card,
            columns=("version", "path"),
            show="headings",
            height=10,
        )
        self.tree.heading("version", text="Version")
        self.tree.heading("path", text="Path")
        self.tree.column("version", width=120)
        self.tree.column("path", width=500)

        self.tree.pack(fill="both", expand=True, padx=12, pady=(4, 8))

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(fill="x", padx=12, pady=(0, 12))

        self.status_label = ttk.Label(
            actions,
            text="",
            style="Muted.TLabel",
        )
        self.status_label.pack(side="left")

        self.refresh_btn = ttk.Button(
            actions,
            text="Refresh",
            style="Subtle.TButton",
            command=self._refresh,
        )
        self.refresh_btn.pack(side="right")

        self._refresh()

    def _refresh(self):
        self.refresh_btn.state(["disabled"])
        self.status_label.config(text="Scanning plugins...")

        for row in self.tree.get_children():
            self.tree.delete(row)

        def _scan():
            plugins = []
            try:
                os.makedirs(self.app.paths.plugins_dir, exist_ok=True)
                for folder in os.listdir(self.app.paths.plugins_dir):
                    p = os.path.join(self.app.paths.plugins_dir, folder)
                    if not os.path.isdir(p):
                        continue
                    manifest = os.path.join(p, "manifest.json")
                    version = "unknown"
                    if os.path.exists(manifest):
                        try:
                            with open(manifest, "r", encoding="utf-8") as f:
                                data = json.load(f)
                                version = data.get("version", "unknown")
                        except Exception as e:
                            append_log(self.app.paths, f"Error reading plugin manifest {manifest}: {e}")
                    plugins.append((version, p))
            except Exception as e:
                append_log(self.app.paths, f"Plugin scan failed: {e}")
            return plugins

        ok, result = retry_operation(_scan, "Plugin directory scan", self.app.paths)
        plugins = result or []

        for version, path in plugins:
            self.tree.insert("", "end", values=(version, path))

        if ok:
            self.status_label.config(text=f"Found {len(plugins)} plugin(s).")
        else:
            self.status_label.config(text="Plugin scan encountered errors. See logs.")

        self.refresh_btn.state(["!disabled"])

# ============================================================================
# AUDIT TIMELINE PAGE (with retry + visual feedback)
# ============================================================================

class AuditPage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Audit Timeline",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text="A chronological record of all Owner-level actions.",
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        self.viewer = scrolledtext.ScrolledText(
            self,
            wrap="word",
            bg="#020617",
            fg=IntentOSTheme.TEXT_PRIMARY,
            insertbackground=IntentOSTheme.TEXT_PRIMARY,
        )
        self.viewer.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 8))

        actions = ttk.Frame(self, style="Card.TFrame")
        actions.grid(row=2, column=0, sticky="e", padx=0, pady=(0, 12))

        self.status_label = ttk.Label(
            actions,
            text="",
            style="Muted.TLabel",
        )
        self.status_label.pack(side="left")

        self.refresh_btn = ttk.Button(
            actions,
            text="Refresh",
            style="Subtle.TButton",
            command=self._refresh,
        )
        self.refresh_btn.pack(side="right")

        self._refresh()

    def _refresh(self):
        self.refresh_btn.state(["disabled"])
        self.status_label.config(text="Loading audit log...")

        path = self.app.paths.audit_log_file

        def _read():
            # self-healing: create empty file if missing
            if not os.path.exists(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write("")
                append_log(self.app.paths, f"Created empty audit log at {path}.")
            with open(path, "r", encoding="utf-8") as f:
                return f.read()

        ok, content = retry_operation(_read, "Audit log read", self.app.paths)

        self.viewer.delete("1.0", tk.END)
        if ok and content is not None:
            self.viewer.insert(tk.END, content)
            self.status_label.config(text="Audit log loaded.")
        else:
            self.viewer.insert(tk.END, "Failed to read audit log after multiple attempts.\n")
            self.status_label.config(text="Audit log read failed.")

        self.refresh_btn.state(["!disabled"])

# ============================================================================
# MAINTENANCE MODE PAGE (with status + safe start)
# ============================================================================

class MaintenancePage(BasePage):
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Maintenance Mode",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "Maintenance Mode locks the system for 1 hour.\n"
                "During this time, updates and migrations are applied.\n"
                "When the timer ends, the console restarts automatically."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(fill="x", padx=12, pady=(4, 4))

        self.start_btn = ttk.Button(
            actions,
            text="Start 1-Hour Maintenance",
            style="Accent.TButton",
            command=self._start_maintenance,
        )
        self.start_btn.pack(side="left")

        self.status_label = ttk.Label(
            card,
            text="",
            style="Muted.TLabel",
        )
        self.status_label.pack(anchor="w", padx=12, pady=(8, 12))

        self._refresh_status()

    def _refresh_status(self):
        ms = self.app.maintenance_state
        if ms.enabled and ms.started_at:
            try:
                start = datetime.fromisoformat(ms.started_at.replace("Z", ""))
                end = start + timedelta(seconds=ms.duration_seconds)
                now = datetime.utcnow()
                remaining = end - now
                seconds_total = int(remaining.total_seconds())
                if seconds_total < 0:
                    self.status_label.config(text="Maintenance period elapsed; waiting for console restart.")
                else:
                    minutes, seconds = divmod(seconds_total, 60)
                    self.status_label.config(
                        text=f"Maintenance active — {minutes}m {seconds}s remaining."
                    )
            except Exception as e:
                append_log(self.app.paths, f"Maintenance status parse error: {e}")
                self.status_label.config(text="Maintenance state invalid; will auto-reset when timer tick runs.")
        else:
            self.status_label.config(text="Maintenance mode is not active.")

        self.after(1000, self._refresh_status)

    def _start_maintenance(self):
        if not self.app.owner:
            messagebox.showerror(
                "Owner Required",
                "Only the Owner can start maintenance mode."
            )
            return

        if self.app.maintenance_state.enabled:
            messagebox.showinfo(
                "Already Active",
                "Maintenance mode is already active."
            )
            return

        if not messagebox.askyesno(
            "Start Maintenance",
            "Begin 1-hour maintenance mode?"
        ):
            return

        self.start_btn.state(["disabled"])
        self.status_label.config(text="Starting maintenance...")

        try:
            ms = self.app.maintenance_state
            ms.enabled = True
            ms.started_at = datetime.utcnow().isoformat() + "Z"
            ms.duration_seconds = 3600

            def _save():
                save_maintenance_state(self.app.paths, ms)

            ok, _ = retry_operation(_save, "Saving maintenance state", self.app.paths)
            if not ok:
                messagebox.showerror(
                    "Maintenance Error",
                    "Failed to persist maintenance state after multiple attempts."
                )
            else:
                self.app.maintenance_state = ms
                append_log(self.app.paths, "Maintenance mode started.")
                append_audit(self.app.paths, "Maintenance mode started.")
                messagebox.showinfo(
                    "Maintenance Started",
                    "Maintenance mode is now active.\nThe console will restart when complete."
                )
        finally:
            self.start_btn.state(["!disabled"])


# ============================================================================
# DIAGNOSTICS PAGE
# ============================================================================

class DiagnosticsPage(BasePage):
    """Run quick diagnostics and surface backend status, file metadata, and simple checks."""
    def __init__(self, master, app):
        super().__init__(master, app)

        self.grid_columnconfigure(0, weight=1)

        card = ttk.Frame(self, style="Card.TFrame")
        card.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))

        _label_card(card, "Diagnostics",
                    font=("Segoe UI Semibold", 16)).pack(anchor="w",
                    pady=(10, 4), padx=12)

        ttk.Label(
            card,
            text=(
                "Quick health & diagnostics for core components. This runs localized checks only."
            ),
            style="Muted.TLabel",
            wraplength=700,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 8))

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.pack(fill="x", padx=12, pady=(0, 12))

        ttk.Button(
            actions,
            text="Run Diagnostics",
            style="Accent.TButton",
            command=self._run_diagnostics,
        ).pack(side="left")

        ttk.Button(
            actions,
            text="Refresh Status",
            style="Subtle.TButton",
            command=self._run_diagnostics,
        ).pack(side="right")

        # Output viewer
        self.viewer = scrolledtext.ScrolledText(
            self,
            wrap="word",
            bg="#020617",
            fg=IntentOSTheme.TEXT_PRIMARY,
            insertbackground=IntentOSTheme.TEXT_PRIMARY,
            height=20,
        )
        self.viewer.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 8))

        # initial run
        self._run_diagnostics()

    def _run_diagnostics(self):
        self.viewer.delete("1.0", tk.END)
        p = self.app.paths

        try:
            self.viewer.insert(tk.END, "Diagnostics run at: " + _ts() + "\n\n")

            # Root engine
            meta = get_engine_metadata(p)
            self.viewer.insert(tk.END, f"Root engine: exists={meta.get('exists')}\n")
            if meta.get("exists"):
                self.viewer.insert(tk.END, f"  size: {meta.get('size_bytes')} bytes\n")
                self.viewer.insert(tk.END, f"  modified: {meta.get('modified')}\n")

            # Backend health
            bh = getattr(self.app, "backend_monitor", None)
            if bh is not None:
                status = bh.status
                self.viewer.insert(tk.END, "Backend monitor:\n")
                self.viewer.insert(tk.END, f"  ok: {status.get('ok')}\n")
                self.viewer.insert(tk.END, f"  last_check: {status.get('last_check')}\n")
                self.viewer.insert(tk.END, f"  error: {status.get('error')}\n")

            # Permissions summary
            features = self.app.permissions.get("features", {}) if isinstance(self.app.permissions, dict) else {}
            self.viewer.insert(tk.END, f"Permissions features: {len(features)}\n")

            # Simple disk checks for core files
            for name, path in [
                ("backend_main", p.backend_main),
                ("dashboard_index", p.dashboard_index),
                ("cli_script", p.cli_script),
            ]:
                exists = os.path.exists(path)
                self.viewer.insert(tk.END, f"{name}: {path} -> {exists}\n")

            append_log(self.app.paths, "Diagnostics run via GUI.")
            append_audit(self.app.paths, "Diagnostics run via GUI.")
        except Exception as e:
            append_log(self.app.paths, f"Diagnostics error: {e}")
            self.viewer.insert(tk.END, f"Diagnostics encountered an error: {e}\n")


# ============================================================================
# PAGE REGISTRATION (AFTER ALL PAGE CLASSES ARE DEFINED)
# ============================================================================

def register_all_pages(app: "IntentOSGUI"):
    """
    Register all pages with the GUI.
    This is called after the GUI object is created.
    """

    pages = {
        "overview": (OverviewPage, "Overview"),
        "engine": (EngineServicesPage, "Engine & Services"),
        "listening": (ListeningPage, "Always Listening"),
        "privacy": (PrivacyDashboardPage, "Privacy Dashboard"),
        "diagnostics": (DiagnosticsPage, "Diagnostics"),
        "subsystems": (SubsystemManagerPage, "Subsystem Manager"),
        "config": (ConfigEditorPage, "Config Editor"),
        "intent": (IntentRunnerPage, "Intent Runner"),
        "logs": (LogsPage, "Logs"),
        "sharing": (DataSharingPage, "Data Sharing"),
        "permissions": (PermissionsPage, "Permissions"),
        "suggestions": (SuggestionsPage, "Suggestions"),
        "plugins": (PluginManagerPage, "Plugins"),
        "audit": (AuditPage, "Audit Timeline"),
        "maintenance": (MaintenancePage, "Maintenance"),
    }

    for key, (cls, label) in pages.items():
        try:
            frame = cls(app.main_container, app)
            app.register_page(key, frame, label)
        except Exception as e:
            append_log(app.paths, f"Failed to register page {key}: {e}")
            # Create a fallback error page
            fallback = ttk.Frame(app.main_container, style="Card.TFrame")
            ttk.Label(
                fallback,
                text=f"Failed to load page '{label}'.\nSee logs for details.",
                style="Danger.TLabel",
                font=("Segoe UI", 14),
            ).pack(padx=20, pady=20)
            app.register_page(key, fallback, label)

    # Default page
    app.show_page("overview")

    # Add auto-suggestion tick handler onto the GUI instance so it has access to pages
    def _auto_suggestion_tick():
        try:
            created = check_intents_and_create_suggestions(app.paths)
            if created:
                append_audit(app.paths, f"Auto suggestions created: {len(created)}")
                send_desktop_notification("IntentOS Suggestions", f"{len(created)} new suggestions created. Open Suggestions page to review.")
                # refresh the Suggestions page if registered
                pg = app.pages.get("suggestions")
                if pg and hasattr(pg, "_refresh"):
                    try:
                        pg._refresh()
                    except Exception:
                        pass
        except Exception as e:
            append_log(app.paths, f"Auto suggestion tick failed: {e}")
        finally:
            # schedule next run in 60 seconds
            try:
                app.after(60000, _auto_suggestion_tick)
            except Exception:
                pass

    # schedule first run
    try:
        app.after(15000, _auto_suggestion_tick)
    except Exception:
        pass

# ============================================================================
# GLOBAL TKINTER EXCEPTION SAFETY HOOK
# ============================================================================

def _global_tk_error_handler(type_, value, tb):
    """
    Catch any Tkinter callback exceptions that escape local handlers.
    Prevents GUI crashes.
    """
    try:
        import traceback
        err = "".join(traceback.format_exception(type_, value, tb))
        print("[IntentOS GUI ERROR]", err, file=sys.stderr)
        # Attempt to log if possible
        # We don't have direct access to app.paths here, so best effort:
        with open("intentos_fallback_error.log", "a", encoding="utf-8") as f:
            f.write(err + "\n")
    except Exception:
        pass

# Install global exception hook
import sys
sys.excepthook = _global_tk_error_handler

# ============================================================================
# FINAL AUTO-REPAIR ON STARTUP
# ============================================================================

def perform_startup_autorepair(app: "IntentOSGUI"):
    """
    Ensures all critical subsystems exist before GUI fully loads.
    This runs BEFORE pages are shown.
    """

    repairs = []

    # Root engine
    if not os.path.exists(app.paths.root_file):
        create_default_root_file(app.paths)
        repairs.append("root engine")

    # Backend
    if not os.path.exists(app.paths.backend_main):
        create_default_backend_main(app.paths)
        repairs.append("backend main.py")

    # Dashboard
    if not os.path.exists(app.paths.dashboard_index):
        create_default_dashboard_index(app.paths)
        repairs.append("dashboard index.html")

    # CLI
    if not os.path.exists(app.paths.cli_script):
        create_default_cli_script(app.paths)
        repairs.append("cli.py")

    # Configs
    if not os.path.exists(app.paths.permissions_file):
        save_permissions(app.paths, load_permissions(app.paths))
        repairs.append("permissions.json")

    if not os.path.exists(app.paths.listening_file):
        save_listening_state(app.paths, load_listening_state(app.paths))
        repairs.append("listening.json")

    if not os.path.exists(app.paths.maintenance_file):
        save_maintenance_state(app.paths, load_maintenance_state(app.paths))
        repairs.append("maintenance.json")

    if repairs:
        append_log(app.paths, f"Startup auto-repair executed: {', '.join(repairs)}")
        append_audit(app.paths, f"Startup auto-repair executed: {', '.join(repairs)}")
# ============================================================================
# MAIN ENTRYPOINT
# ============================================================================

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # Create GUI
    app = IntentOSGUI(repo_root)

    # Auto-repair BEFORE pages load
    perform_startup_autorepair(app)

    # Register all pages
    register_all_pages(app)

    # Start GUI
    app.mainloop()


if __name__ == "__main__":
    main()