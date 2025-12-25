from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from pydantic import BaseModel

from training_orchestrator import TrainingOrchestrator


router = APIRouter(prefix="/admin/training", tags=["admin-training"])


# You likely already have something like this:
def get_current_owner_id() -> str:
    # TODO: integrate with your real auth + speaker ID if desired
    # For now, assume "OWNER" when authenticated through owner console.
    return "OWNER"


def get_orchestrator() -> TrainingOrchestrator:
    # You may want to reuse a singleton in your app state
    return TrainingOrchestrator(
        model_root=Path("./models/current"),
        checkpoint_dir=Path("./models/checkpoints"),
        audit_log_path=Path("./logs/training_audit.log"),
        owner_id="OWNER",
    )


class TrainingRequest(BaseModel):
    reason: str
    git_commit: Optional[str] = None
    metadata: dict = {}


class RollbackRequest(BaseModel):
    checkpoint_id: str


@router.get("/status")
def training_status(
    orchestrator: TrainingOrchestrator = Depends(get_orchestrator),
) -> dict:
    return orchestrator.get_status()


@router.post("/request", status_code=status.HTTP_202_ACCEPTED)
def request_training(
    payload: TrainingRequest,
    background_tasks: BackgroundTasks,
    orchestrator: TrainingOrchestrator = Depends(get_orchestrator),
    owner_id: str = Depends(get_current_owner_id),
) -> dict:
    try:
        job = orchestrator.request_training(
            user_id=owner_id,
            reason=payload.reason,
            git_commit=payload.git_commit,
            metadata=payload.metadata,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))

    # Kick off background training job
    background_tasks.add_task(orchestrator.run_training_job)

    return {"message": "Training job queued.", "job": job.dict()}


@router.post("/rollback")
def rollback_checkpoint(
    payload: RollbackRequest,
    orchestrator: TrainingOrchestrator = Depends(get_orchestrator),
    owner_id: str = Depends(get_current_owner_id),
) -> dict:
    try:
        job = orchestrator.rollback_to_checkpoint(owner_id, checkpoint_id=payload.checkpoint_id)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {"message": "Rollback completed.", "job": job.dict()}