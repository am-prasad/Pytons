"""AgentShield API — Tool simulation endpoint"""
from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from app.schemas.models import (
    PolicyDecision,
    PolicyResult,
    RiskCategory,
    ToolSimulateRequest,
    ToolSimulateResponse,
)
from app.policy.gate import authorize_tool_action
from app.services.tools import execute_tool

import json

router = APIRouter()


@router.post("/tools/simulate", response_model=ToolSimulateResponse)
async def simulate_tool(body: ToolSimulateRequest) -> ToolSimulateResponse:
    """
    Request execution of a predefined simulated tool.
    Authorization is checked independently of any LLM recommendation.
    Sensitive tools are blocked unless the policy gate explicitly permits.
    """
    t0 = time.monotonic()

    # For demo: simulate a benign policy result for safe tools,
    # but require explicit check for sensitive ones.
    # In real use, a prior analysis request's policy_result would be passed in.
    # Here we use a conservative default.
    default_policy = PolicyResult(
        decision=PolicyDecision.ALLOW,
        risk_score=5.0,
        risk_category=RiskCategory.LOW,
        explanation="Default policy for direct tool call (no prior analysis)",
    )

    authorized, auth_reason = authorize_tool_action(body.tool_name, default_policy)
    latency = (time.monotonic() - t0) * 1000

    if not authorized:
        return ToolSimulateResponse(
            tool_name=body.tool_name,
            executed=False,
            authorized=False,
            policy_decision=PolicyDecision.BLOCK,
            result=None,
            explanation=auth_reason,
            latency_ms=round(latency, 2),
        )

    # Execute safe simulated tool
    try:
        result = execute_tool(body.tool_name, body.parameters)
        result_str = json.dumps(result, indent=2)
    except Exception as exc:
        result_str = f"Tool execution error: {exc}"

    latency = (time.monotonic() - t0) * 1000
    return ToolSimulateResponse(
        tool_name=body.tool_name,
        executed=True,
        authorized=True,
        policy_decision=PolicyDecision.ALLOW,
        result=result_str,
        explanation=auth_reason,
        latency_ms=round(latency, 2),
    )


# ─── LangGraph HITL Endpoints (Phase 3) ──────────────────────────────────────

@router.post("/tools/graph/run")
async def run_hitl_graph_endpoint(body: Dict[str, Any]):
    """
    Executes an action through the checkpointed LangGraph HITL state machine.
    Pauses execution at human_approval_gate if a sensitive action is proposed.
    """
    from app.graph.interactive_agent_graph import run_hitl_agent
    prompt = str(body.get("prompt", "Analyze system records"))
    thread_id = body.get("thread_id")
    user = str(body.get("authenticated_user", "secops_analyst"))

    state = await run_hitl_agent(
        prompt=prompt,
        thread_id=thread_id,
        authenticated_user=user,
    )
    return state.model_dump()


@router.post("/tools/graph/resume")
async def resume_hitl_graph_endpoint(body: Dict[str, Any]):
    """
    Resumes a paused LangGraph thread from checkpointer:
    Approves, edits, or rejects the held action and executes to completion.
    """
    from app.graph.interactive_agent_graph import resume_hitl_agent
    thread_id = body.get("thread_id")
    if not thread_id:
        raise HTTPException(status_code=400, detail="Missing required 'thread_id'.")

    decision = str(body.get("decision", "APPROVE")).upper()
    edited_params = body.get("edited_parameters")
    notes = body.get("reviewer_notes")

    try:
        resumed = await resume_hitl_agent(
            thread_id=thread_id,
            decision="APPROVE" if decision == "APPROVE" else "REJECT",
            edited_parameters=edited_params,
            reviewer_notes=notes,
        )
        return resumed.model_dump()
    except ValueError as val_err:
        raise HTTPException(status_code=404, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to resume LangGraph thread: {exc}")
