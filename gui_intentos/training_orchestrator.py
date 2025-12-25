from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel


TrainingStatus = Literal["idle", "pending", "running", "success", "failed", "rolled_back"]


@dataclass
class TrainingCheckpoint:
    id: str
    created_at: float
    path: str
    checksum: str
    parent_id: Optional[str]
    notes: str


class TrainingJobRecord(BaseModel):
    id: str
    started_at: float
    finished_at: Optional[float]
    status: TrainingStatus
    reason: Optional[str] = None
    checkpoint_id: Optional[str] = None
    previous_checkpoint_id: Optional[str] = None
    git_commit: Optional[str] = None
    requested_by: str  # e.g., "OWNER"
    metadata: dict = {}


class TrainingOrchestrator:
    """
    Orchestrates training for IntentOS models with:
    - owner-only control
    - checkpointing & checksums
    - audit log
    - rollback
    """

    def __init__(
        self,
        model_root: Path,
        checkpoint_dir: Path,
        audit_log_path: Path,
        owner_id: str = "OWNER",
    ) -> None:
        self.model_root = model_root
        self.checkpoint_dir = checkpoint_dir
        self.audit_log_path = audit_log_path
        self.owner_id = owner_id

        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._status: TrainingStatus = "idle"
        self._current_job: Optional[TrainingJobRecord] = None

    # ---------------- Owner gating ---------------- #

    def require_owner(self, user_id: str) -> None:
        if user_id != self.owner_id:
            raise PermissionError("Only OWNER can initiate or modify training.")

    # ---------------- Public API ---------------- #

    def get_status(self) -> dict:
        return {
            "status": self._status,
            "current_job": self._current_job.dict() if self._current_job else None,
            "checkpoints": [asdict(c) for c in self._load_checkpoints()],
        }

    def request_training(
        self,
        user_id: str,
        reason: str,
        git_commit: Optional[str],
        metadata: Optional[dict] = None,
    ) -> TrainingJobRecord:
        self.require_owner(user_id)

        if self._status in ("pending", "running"):
            raise RuntimeError("Training already in progress.")

        job_id = f"job-{int(time.time())}"
        job = TrainingJobRecord(
            id=job_id,
            started_at=time.time(),
            finished_at=None,
            status="pending",
            reason=reason,
            checkpoint_id=None,
            previous_checkpoint_id=self._get_current_checkpoint_id(),
            git_commit=git_commit,
            requested_by=user_id,
            metadata=metadata or {},
        )
        self._current_job = job
        self._status = "pending"
        self._append_audit(job)
        return job

    def run_training_job(self) -> TrainingJobRecord:
        """
        This should be called by a background worker or task runner,
        not directly from HTTP request thread.
        """
        if not self._current_job or self._status != "pending":
            raise RuntimeError("No pending training job to run.")

        job = self._current_job
        self._status = "running"
        job.status = "running"
        self._update_audit(job)

        try:
            # 1) Create new checkpoint dir
            checkpoint = self._create_checkpoint_stub(parent_id=job.previous_checkpoint_id)

            # 2) Run actual training pipeline using current model_root,
            #    write outputs to `checkpoint.path`
            self._run_training_pipeline(checkpoint)

            # 3) Compute checksum
            checkpoint.checksum = self._compute_dir_checksum(Path(checkpoint.path))
            self._save_checkpoint(checkpoint)

            # 4) Flip "current" symlink / metadata atomically
            self._activate_checkpoint(checkpoint)

            job.status = "success"
            job.checkpoint_id = checkpoint.id
            job.finished_at = time.time()
            self._status = "success"
            self._update_audit(job)
            return job

        except Exception as e:
            job.status = "failed"
            job.finished_at = time.time()
            job.metadata["error"] = str(e)
            self._status = "failed"
            self._update_audit(job)
            raise

        finally:
            # Clean up in-memory job; status remains last state
            self._current_job = None

    def rollback_to_checkpoint(self, user_id: str, checkpoint_id: str) -> TrainingJobRecord:
        self.require_owner(user_id)

        checkpoints = {c.id: c for c in self._load_checkpoints()}
        if checkpoint_id not in checkpoints:
            raise ValueError(f"Checkpoint {checkpoint_id} not found.")

        job_id = f"rollback-{int(time.time())}"
        job = TrainingJobRecord(
            id=job_id,
            started_at=time.time(),
            finished_at=None,
            status="running",
            reason=f"Rollback to {checkpoint_id}",
            checkpoint_id=checkpoint_id,
            previous_checkpoint_id=self._get_current_checkpoint_id(),
            git_commit=None,
            requested_by=user_id,
            metadata={"type": "rollback"},
        )
        self._current_job = job
        self._status = "running"
        self._append_audit(job)

        try:
            checkpoint = checkpoints[checkpoint_id]
            self._activate_checkpoint(checkpoint)

            job.status = "rolled_back"
            job.finished_at = time.time()
            self._status = "rolled_back"
            self._update_audit(job)
            return job

        finally:
            self._current_job = None

    # ---------------- Internals ---------------- #

    def _run_training_pipeline(self, checkpoint: TrainingCheckpoint) -> None:
        """
        Implement your actual training logic here.

        - Read data/config from self.model_root
        - Train or fine-tune models
        - Save all artifacts under checkpoint.path
        """
        # TODO: call your real training code here.
        # For now, create a dummy file so the directory isn't empty.
        path = Path(checkpoint.path)
        path.mkdir(parents=True, exist_ok=True)
        (path / "MODEL_PLACEHOLDER.txt").write_text("Trained model artifacts go here.\n")

    def _create_checkpoint_stub(self, parent_id: Optional[str]) -> TrainingCheckpoint:
        ts = int(time.time())
        ckpt_id = f"ckpt-{ts}"
        ckpt_path = self.checkpoint_dir / ckpt_id
        return TrainingCheckpoint(
            id=ckpt_id,
            created_at=time.time(),
            path=str(ckpt_path),
            checksum="",
            parent_id=parent_id,
            notes="",
        )

    def _activate_checkpoint(self, checkpoint: TrainingCheckpoint) -> None:
        """
        Atomically update current model directory to point to this checkpoint.
        You can use a symlink, or copy files for simplicity.
        """
        target = Path(checkpoint.path)
        if not target.exists():
            raise FileNotFoundError(f"Checkpoint path missing: {target}")

        # Strategy: clear model_root and copy over from checkpoint
        if self.model_root.exists():
            # Be careful: you may want a backup here too
            shutil.rmtree(self.model_root)
        shutil.copytree(target, self.model_root)

        # Also write a small "CURRENT" file in checkpoint_dir
        current_meta = {
            "current_checkpoint_id": checkpoint.id,
            "activated_at": time.time(),
        }
        (self.checkpoint_dir / "CURRENT.json").write_text(json.dumps(current_meta, indent=2))

    def _compute_dir_checksum(self, path: Path) -> str:
        hasher = hashlib.sha256()
        for file in sorted(path.rglob("*")):
            if file.is_file():
                hasher.update(file.name.encode("utf-8"))
                hasher.update(file.read_bytes())
        return hasher.hexdigest()

    def _load_checkpoints(self) -> list[TrainingCheckpoint]:
        meta_path = self.checkpoint_dir / "CHECKPOINTS.json"
        if not meta_path.exists():
            return []
        data = json.loads(meta_path.read_text())
        return [TrainingCheckpoint(**c) for c in data]

    def _save_checkpoint(self, checkpoint: TrainingCheckpoint) -> None:
        checkpoints = self._load_checkpoints()
        checkpoints.append(checkpoint)
        meta_path = self.checkpoint_dir / "CHECKPOINTS.json"
        meta_path.write_text(json.dumps([asdict(c) for c in checkpoints], indent=2))

    def _get_current_checkpoint_id(self) -> Optional[str]:
        current_path = self.checkpoint_dir / "CURRENT.json"
        if not current_path.exists():
            return None
        data = json.loads(current_path.read_text())
        return data.get("current_checkpoint_id")

    def _append_audit(self, job: TrainingJobRecord) -> None:
        line = json.dumps(job.dict())
        with self.audit_log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _update_audit(self, job: TrainingJobRecord) -> None:
        # Simple approach: rewrite entire log from scratch based on existing + updated job.
        # You can make this more efficient later.
        if not self.audit_log_path.exists():
            self._append_audit(job)
            return

        lines = self.audit_log_path.read_text().splitlines()
        records = [json.loads(l) for l in lines if l.strip()]
        found = False
        for idx, rec in enumerate(records):
            if rec["id"] == job.id:
                records[idx] = job.dict()
                found = True
                break
        if not found:
            records.append(job.dict())

        with self.audit_log_path.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")