"""AgentShield API — Tool simulation endpoint"""
from __future__ import annotations

import time

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
