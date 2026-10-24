"""
AgentShield Documents API Route
Handles document upload (PDF/TXT), extraction, and dual-agent execution:
- POST /api/v1/documents/analyze
- GET /api/v1/alerts
- GET /api/v1/approvals
- POST /api/v1/approvals/resolve
- GET /api/v1/sandbox/outbox
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.core.config import get_settings
from app.graph.agent_workflow import execute_document_security_pipeline
from app.schemas.models import (
    ApprovalDecision,
    ApprovalListResponse,
    DocumentAnalyzeResponse,
    ExecutionMode,
)
from app.services.alerts import get_all_alerts, get_pending_approvals, resolve_approval
from app.services.documents import validate_and_extract_document
from app.services.tools import get_sandbox_exports, get_sandbox_outbox

router = APIRouter()


@router.post("/documents/analyze", response_model=DocumentAnalyzeResponse)
async def analyze_document_endpoint(
    file: UploadFile = File(...),
    task: str = Form(default="Summarize this document and identify its security recommendations."),
    session_id: Optional[str] = Form(default=None),
) -> DocumentAnalyzeResponse:
    """
    Upload and analyze a PDF or TXT document through the full AgentShield security pipeline.
    Runs side-by-side comparison of Unprotected Agent vs Protected Agent.
    """
    settings = get_settings()
    t_start = time.monotonic()

    # Read uploaded content
    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {exc}")

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Validate and extract text
    try:
        doc_meta, pages_data = validate_and_extract_document(file.filename or "document.txt", content)
    except ValueError as val_err:
        err_msg = str(val_err)
        if "Unsupported media type" in err_msg:
            raise HTTPException(status_code=415, detail=err_msg)
        elif "Image-only PDF" in err_msg:
            raise HTTPException(status_code=422, detail=err_msg)
        else:
            raise HTTPException(status_code=400, detail=err_msg)

    # Execute LangGraph Pipeline
    try:
        pipeline_state = await execute_document_security_pipeline(
            task=task,
            doc_meta=doc_meta,
            pages_data=pages_data,
            session_id=session_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {exc}")

    latency = (time.monotonic() - t_start) * 1000

    # Build truthful JSON report for audit download
    json_report = {
        "report_id": f"rep-{pipeline_state.request_id[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "disclaimer": "Experimental analysis; not a guarantee against all prompt injection.",
        "file": {
            "name": doc_meta.filename,
            "type": doc_meta.file_type,
            "pages": doc_meta.pages,
            "extracted_characters": doc_meta.extracted_chars,
            "chunks_total": doc_meta.chunks_total,
            "chunks_sent_to_llm": doc_meta.chunks_sent_to_llm,
            "llm_review_status": doc_meta.llm_review_status,
        },
        "task": task,
        "policy_decision": pipeline_state.overall_decision.value,
        "risk_score": pipeline_state.overall_risk_score,
        "risk_category": pipeline_state.overall_category.value,
        "attack_types": [a.value for a in pipeline_state.attack_types],
        "evidence_count": len(pipeline_state.evidence),
        "unprotected_agent": {
            "model": pipeline_state.unprotected_result.model if pipeline_state.unprotected_result else "none",
            "proposed_actions": pipeline_state.unprotected_result.proposed_actions if pipeline_state.unprotected_result else [],
            "executed_actions": pipeline_state.unprotected_result.executed_actions if pipeline_state.unprotected_result else [],
        },
        "protected_agent": {
            "model": pipeline_state.protected_result.model if pipeline_state.protected_result else "none",
            "proposed_actions": pipeline_state.protected_result.proposed_actions if pipeline_state.protected_result else [],
            "denied_actions": pipeline_state.protected_result.denied_actions if pipeline_state.protected_result else [],
            "executed_actions": pipeline_state.protected_result.executed_actions if pipeline_state.protected_result else [],
        },
        "alerts_generated": len(pipeline_state.alerts),
        "latency_ms": round(latency, 2),
        "execution_mode": pipeline_state.execution_mode.value,
    }

    return DocumentAnalyzeResponse(
        request_id=pipeline_state.request_id,
        timestamp=datetime.now(timezone.utc),
        doc_meta=doc_meta,
        task=task,
        risk_score=pipeline_state.overall_risk_score,
        risk_category=pipeline_state.overall_category,
        policy_decision=pipeline_state.overall_decision,
        attack_types=pipeline_state.attack_types,
        evidence=pipeline_state.evidence,
        chunks=pipeline_state.chunks,
        unprotected_agent=pipeline_state.unprotected_result,
        protected_agent=pipeline_state.protected_result,
        workflow_nodes=pipeline_state.workflow_nodes,
        trace_events=pipeline_state.trace_events,
        alerts=pipeline_state.alerts,
        latency_ms=round(latency, 1),
        execution_mode=pipeline_state.execution_mode,
        judge_model=settings.groq_model,
        agent_model=settings.agent_model,
        langsmith_trace_id=None,
        langsmith_trace_url=None,
        json_report=json_report,
    )


@router.get("/alerts")
async def list_alerts_endpoint():
    """Returns recent alerts dispatched across channels."""
    return {"alerts": [a.model_dump() for a in get_all_alerts(50)]}


@router.get("/approvals", response_model=ApprovalListResponse)
async def list_approvals_endpoint():
    """Lists sensitive tool actions awaiting human review."""
    approvals = get_pending_approvals()
    return ApprovalListResponse(approvals=approvals, total=len(approvals))


@router.post("/approvals/resolve")
async def resolve_approval_endpoint(body: ApprovalDecision):
    """Approve or reject a pending sensitive tool action."""
    resolved = resolve_approval(body.approval_id, body.decision)
    if not resolved:
        raise HTTPException(status_code=404, detail="Approval request not found or already resolved.")
    return {"status": "success", "approval": resolved.model_dump()}


@router.get("/sandbox/outbox")
async def get_sandbox_outbox_endpoint():
    """Inspects actions recorded in the demo sandbox outbox."""
    return {
        "outbox_emails": get_sandbox_outbox(),
        "exports": get_sandbox_exports(),
    }
