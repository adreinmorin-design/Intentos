"""Telemetry upload helpers (owner-approved, batched uploads).

Design goals:
- Only uploads telemetry if telemetry consent is granted and Owner approves via passphrase.
- Batch events from local telemetry.jsonl and POST to a configured endpoint.
- On success, remove uploaded events from local telemetry file; on failure, preserve events.
- Record a small upload history for auditing.
"""
from typing import List, Dict, Any, Optional, Tuple
import os
import json
import uuid
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Import utility functions from the main gui module. These imports are intentionally
# local to avoid import cycles when gui_intentos imports this module later.
from gui_intentos.gui_intentos import IntentOSPaths, get_feature_consent, verify_owner_passphrase, append_log, _ts


def _telemetry_jsonl_path(paths: IntentOSPaths) -> str:
    return os.path.join(paths.config_dir, "telemetry.jsonl")


def _upload_history_path(paths: IntentOSPaths) -> str:
    return os.path.join(paths.config_dir, "telemetry_upload_history.jsonl")


def _read_local_telemetry(paths: IntentOSPaths) -> List[Dict[str, Any]]:
    p = _telemetry_jsonl_path(paths)
    events = []
    if not os.path.exists(p):
        return events
    try:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
    except Exception as e:
        append_log(paths, f"Failed reading local telemetry: {e}")
    return events


def _write_local_telemetry(paths: IntentOSPaths, events: List[Dict[str, Any]]) -> bool:
    p = _telemetry_jsonl_path(paths)
    try:
        if not events:
            if os.path.exists(p):
                os.remove(p)
            return True
        with open(p, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        return True
    except Exception as e:
        append_log(paths, f"Failed writing local telemetry: {e}")
        return False


def _record_upload_history(paths: IntentOSPaths, batch_id: str, size: int, ok: bool, report: str) -> None:
    p = _upload_history_path(paths)
    entry = {"id": batch_id, "ts": _ts(), "size": size, "ok": bool(ok), "report": str(report)}
    try:
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        append_log(paths, f"Failed to record upload history: {e}")


def upload_all_queued(paths: IntentOSPaths, endpoint: str, owner_passphrase: str, batch_size: int = 50, timeout: int = 6, dry_run: bool = False) -> Tuple[bool, str]:
    """Attempt to upload all queued telemetry events in batches.

    Returns (ok: bool, report: str).
    Requires telemetry consent and owner_passphrase verification.
    On success, removes uploaded events from local telemetry file.
    """
    try:
        if not get_feature_consent(paths, "telemetry"):
            msg = "Telemetry consent not granted; refusing to upload"
            append_log(paths, msg)
            return False, msg
        if not verify_owner_passphrase(paths, owner_passphrase):
            msg = "Owner verification failed; refusing to upload telemetry"
            append_log(paths, msg)
            return False, msg

        events = _read_local_telemetry(paths)
        if not events:
            return True, "No telemetry to upload"

        all_report_lines = []
        while events:
            batch = events[:batch_size]
            batch_id = uuid.uuid4().hex
            payload = {"id": batch_id, "ts": _ts(), "events": batch}
            # If dry_run, just pretend it succeeded
            if dry_run:
                _record_upload_history(paths, batch_id, len(batch), True, "dry_run")
                all_report_lines.append(f"Dry-run: uploaded batch {batch_id} size={len(batch)}")
                events = events[len(batch):]
                continue

            # Attempt HTTP POST
            try:
                req = Request(endpoint, method="POST", data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
                with urlopen(req, timeout=timeout) as resp:
                    status = getattr(resp, "status", None) or getattr(resp, "code", None)
                    if status and 200 <= int(status) < 300:
                        _record_upload_history(paths, batch_id, len(batch), True, f"HTTP {status}")
                        all_report_lines.append(f"Uploaded batch {batch_id} size={len(batch)} status={status}")
                        # remove successful batch
                        events = events[len(batch):]
                        # continue to next batch
                        continue
                    else:
                        report = f"HTTP {status}"
                        _record_upload_history(paths, batch_id, len(batch), False, report)
                        all_report_lines.append(f"Failed batch {batch_id}: {report}")
                        break
            except HTTPError as e:
                report = f"HTTPError: {e.code} {e.reason}"
                _record_upload_history(paths, batch_id, len(batch), False, report)
                all_report_lines.append(f"Failed batch {batch_id}: {report}")
                break
            except URLError as e:
                report = f"URLError: {e.reason}"
                _record_upload_history(paths, batch_id, len(batch), False, report)
                all_report_lines.append(f"Failed batch {batch_id}: {report}")
                break
            except Exception as e:
                report = f"Error: {e}"
                _record_upload_history(paths, batch_id, len(batch), False, report)
                all_report_lines.append(f"Failed batch {batch_id}: {report}")
                break

        # write back remaining events
        _write_local_telemetry(paths, events)
        ok = len(events) == 0
        return ok, "\n".join(all_report_lines)

    except Exception as e:
        append_log(paths, f"Telemetry upload failed: {e}")
        return False, str(e)
