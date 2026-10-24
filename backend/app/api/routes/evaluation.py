"""AgentShield API — Evaluation endpoints"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, BackgroundTasks

from app.schemas.models import EvaluationResult, EvaluationRunRequest
from app.evaluation.runner import run_evaluation, run_multi_config_evaluation
from app.storage.database import get_latest_evaluation

import logging

logger = logging.getLogger(__name__)
router = APIRouter()

_running = False


@router.post("/evaluate", response_model=EvaluationResult)
async def run_eval(body: EvaluationRunRequest) -> EvaluationResult:
    """
    Run the evaluation on the labeled dataset and return computed metrics.
    This executes the full pipeline for each example — may take 30–120 seconds.
    """
    global _running
    if _running:
        raise HTTPException(status_code=429, detail="Evaluation already running. Please wait.")

    _running = True
    try:
        result = await run_evaluation(
            dataset_path=body.dataset_path,
            max_examples=body.max_examples,
        )
        return result
    except Exception as exc:
        logger.error("Evaluation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Evaluation error: {str(exc)[:200]}")
    finally:
        _running = False


@router.post("/evaluate/multi-config")
async def run_multi_eval(body: EvaluationRunRequest):
    """
    Run evaluation across (a) baseline, (b) baseline+judge, (c) full pipeline
    and return the consolidated report with gate enforcement checks.
    """
    global _running
    if _running:
        raise HTTPException(status_code=429, detail="Evaluation already running. Please wait.")

    _running = True
    try:
        report = await run_multi_config_evaluation(
            dataset_path=body.dataset_path,
            max_examples=body.max_examples,
        )
        return report
    except Exception as exc:
        logger.error("Multi-config evaluation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Evaluation error: {str(exc)[:200]}")
    finally:
        _running = False


@router.get("/evaluate/results", response_model=EvaluationResult)
async def get_latest_results() -> EvaluationResult:
    """Returns the latest completed evaluation result."""
    result = get_latest_evaluation()
    if not result:
        raise HTTPException(
            status_code=404,
            detail="No evaluation results found. Run POST /api/v1/evaluate first.",
        )
    return result

