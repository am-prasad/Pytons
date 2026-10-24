"""AgentShield API — Analyze endpoint (POST /api/v1/analyze)"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, HTTPException, Request

from app.schemas.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    AttackType,
    EvidenceSnippet,
    ExecutionMode,
    PolicyDecision,
    SecurityEvent,
    SourceType,
)
from app.graph.workflow import run_security_pipeline
from app.core.config import get_settings
from app.storage.database import save_security_event

import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: Request, body: AnalyzeRequest) -> AnalyzeResponse:
    """
    Run the full AgentShield security pipeline on submitted text.
    Returns risk assessment, evidence, policy decision, and workflow trace.
    """
    settings = get_settings()
    t_start = time.monotonic()

    # Enforce max input length
    if len(body.text) > settings.max_input_length:
        raise HTTPException(
            status_code=413,
            detail=f"Input too large. Maximum {settings.max_input_length} characters allowed.",
        )

    try:
        state = await run_security_pipeline(body)
    except Exception as exc:
        logger.error("Pipeline error: %s", exc)
        raise HTTPException(status_code=500, detail="Security pipeline error")

    latency = (time.monotonic() - t_start) * 1000

    # Determine execution mode
    exec_mode = ExecutionMode.FULL if settings.groq_configured else ExecutionMode.LOCAL_BASELINE

    # Collect attack types from contextual findings
    attack_types: List[AttackType] = []
    if state.contextual_findings and state.contextual_findings.attack_category != AttackType.NONE:
        attack_types.append(state.contextual_findings.attack_category)

    # Collect evidence from both layers
    evidence: List[EvidenceSnippet] = []
    if state.contextual_findings:
        evidence.extend(state.contextual_findings.evidence)

    # Add scanner evidence
    if state.scanner_findings and state.scanner_findings.indicators_found:
        for ind in state.scanner_findings.indicators_found[:5]:
            evidence.append(
                EvidenceSnippet(
                    text=ind,
                    indicator="Pattern match",
                    layer="scanner",
                )
            )

    # Ensure policy result exists
    from app.schemas.models import PolicyResult, RiskCategory
    policy_result = state.policy_result or PolicyResult(
        decision=PolicyDecision.ALLOW,
        risk_score=0.0,
        risk_category=RiskCategory.LOW,
        explanation="Pipeline completed without policy gate result",
    )

    # Ensure other findings exist
    from app.schemas.models import ScannerFindings, ContextualFindings, SessionCorrelation
    scanner_findings = state.scanner_findings or ScannerFindings()
    contextual_findings = state.contextual_findings or ContextualFindings()
    session_correlation = state.session_correlation or SessionCorrelation()

    request_id = state.request_id or str(uuid.uuid4())

    # Persist security event
    event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        request_id=request_id,
        session_id=body.session_id,
        timestamp=datetime.now(timezone.utc),
        source_type=body.source_type.value,
        risk_score=policy_result.risk_score,
        risk_category=policy_result.risk_category.value,
        policy_decision=policy_result.decision.value,
        attack_types=[a.value for a in attack_types],
        execution_mode=exec_mode.value,
        latency_ms=round(latency, 1),
        summary=f"{policy_result.decision.value}: {policy_result.explanation[:100]}",
    )
    save_security_event(event)

    return AnalyzeResponse(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        source_type=body.source_type,
        session_id=body.session_id,
        risk_score=policy_result.risk_score,
        risk_category=policy_result.risk_category,
        policy_decision=policy_result.decision,
        attack_types=attack_types,
        evidence=evidence,
        scanner_findings=scanner_findings,
        contextual_findings=contextual_findings,
        session_correlation=session_correlation,
        policy_result=policy_result,
        tool_action=None,
        workflow_nodes=state.workflow_nodes,
        trace_events=state.trace_events,
        latency_ms=round(latency, 1),
        execution_mode=exec_mode,
        langsmith_trace_id=None,
    )
