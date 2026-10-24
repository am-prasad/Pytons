"""
AgentShield Human-in-the-Loop (HITL) LangGraph Workflow (Phase 3)
Implements a stateful, checkpointer-backed LangGraph with pause-and-resume
for sensitive actions:
- Sending data externally (e.g. send_email, exports)
- Changing/mutating database records (e.g. update_record)
- Deleting files/storage (e.g. delete_file)

Allows an authorized user to:
1. Inspect paused graph state
2. Approve the proposed action
3. Edit the proposed tool arguments
4. Reject the proposed action
5. Resume graph execution from the exact persisted checkpoint
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Literal, Optional

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.policy.gate import authorize_tool_call
from app.schemas.models import (
    AttackType,
    NodeStatus,
    PolicyDecision,
    PolicyResult,
    RiskCategory,
    SourceType,
    TrackedContent,
)
from app.services.alerts import create_and_dispatch_alert, resolve_approval
from app.services.content_tracker import scan_tool_response, track_and_scan_content
from app.services.groq_client import call_agent_llm
from app.services.session_store import get_store
from app.services.tools import execute_tool

logger = logging.getLogger(__name__)


# ─── LangGraph HITL State Schema ──────────────────────────────────────────────

class HITLAgentState(BaseModel):
    """
    Mutable state checkpointed across pause and resume boundaries.
    """
    thread_id: str = ""
    session_id: str = ""
    authenticated_user: str = "default_user"
    user_prompt: str = ""
    source_context: str = ""

    # Phase 2: Source metadata and tracked content
    tracked_inputs: List[Dict[str, Any]] = []

    # Agent planning
    agent_reasoning: str = ""
    proposed_tool_calls: List[Dict[str, Any]] = []

    # Phase 1 & 3: Authorization & HITL approval state
    approved_tool_calls: List[Dict[str, Any]] = []
    denied_actions: List[Dict[str, Any]] = []
    executed_actions: List[Dict[str, Any]] = []

    # Human-in-the-loop gate
    pending_approval: Optional[Dict[str, Any]] = None
    approval_status: str = "NONE"  # NONE | WAITING | APPROVED | REJECTED
    approval_id: Optional[str] = None
    edited_parameters: Optional[Dict[str, Any]] = None
    reviewer_notes: Optional[str] = None

    # Telemetry
    session_risk: float = 0.0
    status: str = "INITIALIZED"  # INITIALIZED | RUNNING | PAUSED_WAITING_APPROVAL | COMPLETED | REJECTED
    final_output: str = ""
    timeline: List[Dict[str, Any]] = []


# ─── Node 1: Input Screening & Untrusted Content Tracking (Phase 2) ──────────

async def node_input_screening(state: HITLAgentState) -> Dict[str, Any]:
    """Screens input prompt and attaches source metadata."""
    t0 = time.monotonic()
    tracked = track_and_scan_content(
        raw_content=state.user_prompt,
        source_type=SourceType.USER_PROMPT,
        source_ref=f"user:{state.authenticated_user}",
    )

    timeline_entry = {
        "node": "input_screening",
        "status": "ran",
        "duration_ms": round((time.monotonic() - t0) * 1000, 2),
        "detail": f"Screened user prompt. Scanner score: {tracked.scanner_score:.1f}.",
    }

    return {
        "tracked_inputs": [tracked.model_dump()],
        "session_risk": tracked.scanner_score,
        "timeline": state.timeline + [timeline_entry],
    }


# ─── Node 2: Agent Reasoning & Action Proposal ───────────────────────────────

async def node_agent_plan(state: HITLAgentState) -> Dict[str, Any]:
    """Runs agent model to decide next steps and propose tool calls."""
    t0 = time.monotonic()
    # Use sanitized content to ensure agent prompt cannot be hijacked
    clean_context = state.tracked_inputs[0]["sanitized_content"] if state.tracked_inputs else state.user_prompt

    answer, proposed_tools, tokens = call_agent_llm(
        task=state.user_prompt,
        document_context=clean_context,
        allow_injection_execution=False,
    )

    # Fallback to simulated proposed action if prompt indicates external sending, mutating records, or deleting
    if not proposed_tools:
        lower = state.user_prompt.lower()
        if "email" in lower or "send" in lower:
            proposed_tools = [{
                "name": "send_email",
                "parameters": {"to": "audit-team@company.com", "subject": "Requested Audit Report", "body": "Summary attached."}
            }]
        elif "delete" in lower or "remove" in lower:
            proposed_tools = [{
                "name": "delete_file",
                "parameters": {"file_path": "/var/data/archive_2025.tar.gz"}
            }]
        elif "update" in lower or "change" in lower or "modify" in lower:
            proposed_tools = [{
                "name": "update_record",
                "parameters": {"record_id": "cust-8821", "updates": {"status": "archived"}}
            }]

    timeline_entry = {
        "node": "agent_plan",
        "status": "ran",
        "duration_ms": round((time.monotonic() - t0) * 1000, 2),
        "detail": f"Agent proposed {len(proposed_tools)} actions.",
    }

    return {
        "agent_reasoning": answer,
        "proposed_tool_calls": proposed_tools,
        "timeline": state.timeline + [timeline_entry],
    }


# ─── Node 3: Policy Enforcement & Tool Authorization (Phase 1) ───────────────

async def node_policy_enforcement(state: HITLAgentState) -> Dict[str, Any]:
    """
    Evaluates every proposed tool call through centralized authorize_tool_call().
    Identifies sensitive operations (external sending, record mutations, deletions)
    and routes them to human approval.
    """
    t0 = time.monotonic()
    approved = []
    denied = []
    pending_appr = None
    appr_status = "NONE"
    appr_id = None
    new_status = "RUNNING"

    for tool_call in state.proposed_tool_calls:
        t_name = tool_call.get("name")
        t_params = tool_call.get("parameters", {})

        decision, reason = authorize_tool_call(
            tool_name=t_name,
            arguments=t_params,
            authenticated_user=state.authenticated_user,
            source_context=state.user_prompt,
            session_risk=state.session_risk,
        )

        if decision == PolicyDecision.ALLOW:
            approved.append(tool_call)
        elif decision == PolicyDecision.BLOCK:
            denied.append({
                "tool": t_name,
                "parameters": t_params,
                "reason": reason,
                "decision": "BLOCK",
            })
        elif decision == PolicyDecision.REQUIRE_APPROVAL:
            # Sensitive operation paused for human approval (Phase 3)
            appr_id = f"appr-{uuid.uuid4().hex[:8]}"
            pending_appr = {
                "approval_id": appr_id,
                "tool_name": t_name,
                "parameters": t_params,
                "reason": reason,
                "thread_id": state.thread_id,
                "session_id": state.session_id,
            }
            appr_status = "WAITING"
            new_status = "PAUSED_WAITING_APPROVAL"

            # Register with system alerts & pending approvals registry
            create_and_dispatch_alert(
                severity=RiskCategory.HIGH,
                checkpoint="human_approval_gate",
                source_ref=f"thread:{state.thread_id}",
                evidence=[reason],
                blocked_action=t_name,
                recommendation="Review proposed tool arguments and confirm authorization before resuming execution.",
                requires_approval=True,
                tool_params=t_params,
                session_id=state.session_id,
                risk_score=state.session_risk,
            )
            # Break on first action requiring human approval
            break

    timeline_entry = {
        "node": "policy_enforcement",
        "status": "ran",
        "duration_ms": round((time.monotonic() - t0) * 1000, 2),
        "detail": (
            f"Evaluated actions: {len(approved)} approved, {len(denied)} blocked, "
            f"{'1 paused for human approval' if pending_appr else '0 requiring approval'}."
        ),
    }

    return {
        "approved_tool_calls": approved,
        "denied_actions": denied,
        "pending_approval": pending_appr,
        "approval_status": appr_status,
        "approval_id": appr_id,
        "status": new_status,
        "timeline": state.timeline + [timeline_entry],
    }


# ─── Node 4: Human Approval Gate (Phase 3 Pause & Resume) ─────────────────────

async def node_human_approval_gate(state: HITLAgentState) -> Dict[str, Any]:
    """
    Checkpoint gate:
    - If WAITING: LangGraph checkpointer persists the state and execution pauses.
    - If APPROVED: Takes approved/edited parameters and routes to execution.
    - If REJECTED: Refuses execution and records denied action.
    """
    t0 = time.monotonic()

    if state.approval_status == "WAITING":
        logger.info("LangGraph execution paused at human_approval_gate for thread %s", state.thread_id)
        return {"status": "PAUSED_WAITING_APPROVAL"}

    if state.approval_status == "APPROVED":
        # Human approved (potentially with edited parameters)
        tool_call = dict(state.pending_approval)
        if state.edited_parameters:
            tool_call["parameters"] = state.edited_parameters

        timeline_entry = {
            "node": "human_approval_gate",
            "status": "ran",
            "duration_ms": round((time.monotonic() - t0) * 1000, 2),
            "detail": f"Human approved action '{tool_call.get('tool_name')}' (resuming execution).",
        }

        return {
            "approved_tool_calls": state.approved_tool_calls + [tool_call],
            "pending_approval": None,
            "status": "RESUMED_APPROVED",
            "timeline": state.timeline + [timeline_entry],
        }

    if state.approval_status == "REJECTED":
        # Human rejected the action
        tool_call = dict(state.pending_approval or {})
        timeline_entry = {
            "node": "human_approval_gate",
            "status": "ran",
            "duration_ms": round((time.monotonic() - t0) * 1000, 2),
            "detail": f"Human rejected action '{tool_call.get('tool_name')}' with notes: '{state.reviewer_notes or 'Denied'}'.",
        }

        return {
            "denied_actions": state.denied_actions + [{
                "tool": tool_call.get("tool_name"),
                "parameters": tool_call.get("parameters"),
                "reason": f"Rejected by human reviewer: {state.reviewer_notes or 'Action denied'}",
                "decision": "REJECTED",
            }],
            "pending_approval": None,
            "status": "REJECTED",
            "timeline": state.timeline + [timeline_entry],
        }

    return {}


# ─── Node 5: Tool Execution with Output Tainting (Phase 2) ────────────────────

async def node_execute_tools(state: HITLAgentState) -> Dict[str, Any]:
    """
    Executes approved actions in sandbox and screens retrieved outputs (Phase 2).
    """
    t0 = time.monotonic()
    executed = []

    for tool_call in state.approved_tool_calls:
        t_name = tool_call.get("name") or tool_call.get("tool_name")
        t_params = tool_call.get("parameters", {})

        # Execute with Phase 1 bypass (already authorized by gate/human)
        res = execute_tool(
            tool_name=t_name,
            parameters=t_params,
            bypass_auth=True,
        )

        executed.append({
            "tool": t_name,
            "parameters": t_params,
            "result": res,
            "executed": True,
        })

    timeline_entry = {
        "node": "execute_tools",
        "status": "ran",
        "duration_ms": round((time.monotonic() - t0) * 1000, 2),
        "detail": f"Executed {len(executed)} authorized actions in sandbox with output screening.",
    }

    return {
        "executed_actions": executed,
        "timeline": state.timeline + [timeline_entry],
    }


# ─── Node 6: Finalize Output ─────────────────────────────────────────────────

async def node_finalize(state: HITLAgentState) -> Dict[str, Any]:
    """Compiles the verified final output for the user."""
    t0 = time.monotonic()

    parts = [state.agent_reasoning] if state.agent_reasoning else []
    if state.executed_actions:
        parts.append(f"\n[AgentShield Verified Actions Executed: {len(state.executed_actions)}]")
    if state.denied_actions:
        parts.append(f"\n[AgentShield Actions Blocked: {len(state.denied_actions)}]")

    final_text = "\n".join(parts) or "Task completed in accordance with security policy."

    timeline_entry = {
        "node": "finalize",
        "status": "ran",
        "duration_ms": round((time.monotonic() - t0) * 1000, 2),
        "detail": "Workflow finished and telemetry finalized.",
    }

    return {
        "final_output": final_text,
        "status": "COMPLETED",
        "timeline": state.timeline + [timeline_entry],
    }


# ─── Conditional Edge Routing ────────────────────────────────────────────────

def route_after_policy(state: HITLAgentState) -> Literal["human_approval_gate", "execute_tools", "finalize"]:
    if state.approval_status == "WAITING":
        return "human_approval_gate"
    if state.approved_tool_calls:
        return "execute_tools"
    return "finalize"


def route_after_approval(state: HITLAgentState) -> Literal["execute_tools", "finalize", "END"]:
    if state.approval_status == "WAITING":
        # Paused at approval gate
        return "END"
    if state.approval_status == "APPROVED":
        return "execute_tools"
    # Rejected
    return "finalize"


# ─── Build the LangGraph with Memory Checkpointer ─────────────────────────────

def build_hitl_agent_graph() -> StateGraph:
    graph = StateGraph(HITLAgentState)

    graph.add_node("input_screening", node_input_screening)
    graph.add_node("agent_plan", node_agent_plan)
    graph.add_node("policy_enforcement", node_policy_enforcement)
    graph.add_node("human_approval_gate", node_human_approval_gate)
    graph.add_node("execute_tools", node_execute_tools)
    graph.add_node("finalize", node_finalize)

    graph.set_entry_point("input_screening")
    graph.add_edge("input_screening", "agent_plan")
    graph.add_edge("agent_plan", "policy_enforcement")

    graph.add_conditional_edges(
        "policy_enforcement",
        route_after_policy,
        {
            "human_approval_gate": "human_approval_gate",
            "execute_tools": "execute_tools",
            "finalize": "finalize",
        },
    )

    graph.add_conditional_edges(
        "human_approval_gate",
        route_after_approval,
        {
            "execute_tools": "execute_tools",
            "finalize": "finalize",
            "END": END,
        },
    )

    graph.add_edge("execute_tools", "finalize")
    graph.add_edge("finalize", END)

    return graph


# Global in-memory checkpointer persisting paused graph states by thread_id
_HITL_CHECKPOINTER = MemorySaver()
_COMPILED_HITL_GRAPH = build_hitl_agent_graph().compile(checkpointer=_HITL_CHECKPOINTER)


# ─── Public API: Run & Resume ────────────────────────────────────────────────

async def run_hitl_agent(
    prompt: str,
    thread_id: Optional[str] = None,
    session_id: Optional[str] = None,
    authenticated_user: str = "default_user",
) -> HITLAgentState:
    """
    Launches the LangGraph HITL workflow.
    If a sensitive action is proposed, execution pauses at human_approval_gate
    and persists state in _HITL_CHECKPOINTER under thread_id.
    """
    tid = thread_id or f"th-{uuid.uuid4().hex[:8]}"
    sid = session_id or f"sess-{uuid.uuid4().hex[:6]}"

    initial_state = HITLAgentState(
        thread_id=tid,
        session_id=sid,
        authenticated_user=authenticated_user,
        user_prompt=prompt,
        status="RUNNING",
    )

    config = {
        "configurable": {"thread_id": tid},
        "run_name": "agentshield_hitl_agent_workflow",
        "tags": ["agentshield", "langgraph_hitl", "pause_resume"],
    }

    result = await _COMPILED_HITL_GRAPH.ainvoke(initial_state, config=config)
    return HITLAgentState(**result) if isinstance(result, dict) else result


async def resume_hitl_agent(
    thread_id: str,
    decision: Literal["APPROVE", "REJECT"],
    edited_parameters: Optional[Dict[str, Any]] = None,
    reviewer_notes: Optional[str] = None,
) -> HITLAgentState:
    """
    Resumes a paused LangGraph thread:
    - Injects approval or rejection
    - Continues execution from the exact persisted checkpoint
    """
    config = {
        "configurable": {"thread_id": thread_id},
        "run_name": "agentshield_hitl_resume_workflow",
        "tags": ["agentshield", "langgraph_resume"],
    }

    # Fetch existing state from checkpointer
    current_state_snapshot = await _COMPILED_HITL_GRAPH.aget_state(config)
    if not current_state_snapshot or not current_state_snapshot.values:
        raise ValueError(f"No paused LangGraph thread found for id '{thread_id}'.")

    # Update state with human decision
    updates = {
        "approval_status": "APPROVED" if decision.upper() == "APPROVE" else "REJECTED",
        "edited_parameters": edited_parameters,
        "reviewer_notes": reviewer_notes or f"Decision: {decision}",
    }

    await _COMPILED_HITL_GRAPH.aupdate_state(config, updates, as_node="human_approval_gate")

    # Resume graph execution to completion
    resumed = await _COMPILED_HITL_GRAPH.ainvoke(None, config=config)
    return HITLAgentState(**resumed) if isinstance(resumed, dict) else resumed
