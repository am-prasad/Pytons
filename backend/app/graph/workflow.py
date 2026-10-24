"""
AgentShield LangGraph Security Workflow
Implements the full multi-layer security pipeline as a typed state graph.
Each node is an explicit, named security checkpoint.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional

from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig
from pydantic import BaseModel

from app.schemas.models import (
    AnalyzeRequest,
    AttackType,
    ContextualFindings,
    EvidenceSnippet,
    ExecutionMode,
    NodeStatus,
    PolicyDecision,
    PolicyResult,
    RiskCategory,
    ScannerFindings,
    SessionCorrelation,
    SourceType,
    TraceEvent,
    WorkflowNode,
)
from app.services import scanner as scanner_svc
from app.services import contextual_analyzer as ctx_svc
from app.services.session_store import get_store
from app.policy import gate as policy_gate

import logging

logger = logging.getLogger(__name__)


# ─── Typed Graph State ─────────────────────────────────────────────────────────

class GraphState(BaseModel):
    """Mutable state passed through every workflow node."""
    # Input
    request_id: str = ""
    session_id: Optional[str] = None
    text: str = ""
    source_type: SourceType = SourceType.USER_PROMPT
    scenario_id: Optional[str] = None

    # Intermediate results (populated by nodes)
    normalized_text: str = ""
    scanner_findings: Optional[ScannerFindings] = None
    contextual_findings: Optional[ContextualFindings] = None
    session_correlation: Optional[SessionCorrelation] = None
    policy_result: Optional[PolicyResult] = None

    # Audit trail
    workflow_nodes: List[WorkflowNode] = []
    trace_events: List[TraceEvent] = []

    # Timing
    start_time: float = 0.0

    # Error tracking
    error: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


# ─── Helper: Record a workflow node ───────────────────────────────────────────

def _record_node(
    state: GraphState,
    name: str,
    status: NodeStatus,
    start_ns: float,
    detail: Optional[str] = None,
) -> None:
    duration = (time.monotonic() - start_ns) * 1000
    state.workflow_nodes.append(
        WorkflowNode(name=name, status=status, duration_ms=round(duration, 2), detail=detail)
    )
    state.trace_events.append(
        TraceEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=name,
            status=status.value,
            duration_ms=round(duration, 2),
            detail=detail,
        )
    )


# ─── Node 1: ingest_input ─────────────────────────────────────────────────────

def ingest_input(state: GraphState) -> GraphState:
    t0 = time.monotonic()
    try:
        # Normalize: strip, truncate, mark as untrusted
        normalized = state.text.strip()[:8000]
        state.normalized_text = normalized
        _record_node(state, "ingest_input", NodeStatus.RAN, t0,
                     f"Source: {state.source_type.value}, length: {len(normalized)} chars")
    except Exception as exc:
        state.error = str(exc)
        _record_node(state, "ingest_input", NodeStatus.ERROR, t0, str(exc))
    return state


# ─── Node 2: scan_input ───────────────────────────────────────────────────────

def scan_input(state: GraphState) -> GraphState:
    t0 = time.monotonic()
    try:
        findings = scanner_svc.scan(state.normalized_text)
        state.scanner_findings = findings
        _record_node(state, "scan_input", NodeStatus.RAN, t0,
                     f"{len(findings.patterns_matched)} patterns matched, score={findings.raw_score:.1f}")
    except Exception as exc:
        state.error = str(exc)
        state.scanner_findings = ScannerFindings()
        _record_node(state, "scan_input", NodeStatus.ERROR, t0, str(exc))
    return state


# ─── Node 3: contextual_analysis ──────────────────────────────────────────────

async def contextual_analysis(state: GraphState) -> GraphState:
    t0 = time.monotonic()
    try:
        scanner_score = state.scanner_findings.raw_score if state.scanner_findings else 0.0
        findings = await ctx_svc.analyze(
            text=state.normalized_text,
            source_type=state.source_type,
            scanner_score=scanner_score,
        )
        state.contextual_findings = findings
        _record_node(state, "contextual_analysis", NodeStatus.RAN, t0,
                     f"Attack: {findings.attack_category.value}, confidence={findings.confidence:.2f}, provider={findings.provider}")
    except Exception as exc:
        state.error = str(exc)
        state.contextual_findings = ContextualFindings(provider="error", note=str(exc))
        _record_node(state, "contextual_analysis", NodeStatus.ERROR, t0, str(exc))
    return state


# ─── Node 4: correlate_session_risk ───────────────────────────────────────────

def correlate_session_risk(state: GraphState) -> GraphState:
    t0 = time.monotonic()
    try:
        store = get_store()
        correlation = store.get_correlation(state.session_id)
        state.session_correlation = correlation
        detail = (
            f"Session '{state.session_id}': {correlation.prior_risk_events} prior risky events"
            if state.session_id
            else "No session ID provided"
        )
        _record_node(state, "correlate_session_risk", NodeStatus.RAN, t0, detail)
    except Exception as exc:
        state.error = str(exc)
        state.session_correlation = SessionCorrelation()
        _record_node(state, "correlate_session_risk", NodeStatus.ERROR, t0, str(exc))
    return state


# ─── Node 5: policy_gate ──────────────────────────────────────────────────────

def run_policy_gate(state: GraphState) -> GraphState:
    t0 = time.monotonic()
    try:
        result = policy_gate.decide(
            scanner=state.scanner_findings or ScannerFindings(),
            contextual=state.contextual_findings or ContextualFindings(),
            session=state.session_correlation or SessionCorrelation(),
            source_type=state.source_type,
        )
        state.policy_result = result
        _record_node(state, "policy_gate", NodeStatus.RAN, t0,
                     f"Decision: {result.decision.value}, risk={result.risk_score:.1f}")
    except Exception as exc:
        state.error = str(exc)
        # Fail-safe: block on error
        state.policy_result = PolicyResult(
            decision=PolicyDecision.BLOCK,
            risk_score=100.0,
            risk_category=RiskCategory.CRITICAL,
            explanation=f"Policy gate error — defaulting to BLOCK: {exc}",
            blocked_reason=str(exc),
        )
        _record_node(state, "policy_gate", NodeStatus.ERROR, t0, str(exc))
    return state


# ─── Node 6: record_security_event ────────────────────────────────────────────

def record_security_event(state: GraphState) -> GraphState:
    t0 = time.monotonic()
    try:
        if state.session_id and state.policy_result:
            store = get_store()
            attack_types = []
            if state.contextual_findings and state.contextual_findings.attack_category != AttackType.NONE:
                attack_types.append(state.contextual_findings.attack_category.value)
            store.add_event(
                session_id=state.session_id,
                risk_score=state.policy_result.risk_score,
                decision=state.policy_result.decision,
                attack_types=attack_types,
                request_id=state.request_id,
            )
        _record_node(state, "record_security_event", NodeStatus.RAN, t0,
                     "Security event recorded")
    except Exception as exc:
        _record_node(state, "record_security_event", NodeStatus.ERROR, t0, str(exc))
    return state


# ─── Conditional routing ───────────────────────────────────────────────────────

def route_after_policy(state: GraphState) -> str:
    """Route based on policy decision."""
    if state.policy_result is None:
        return "record_security_event"
    decision = state.policy_result.decision
    if decision == PolicyDecision.BLOCK:
        return "record_security_event"
    if decision == PolicyDecision.QUARANTINE:
        return "record_security_event"
    return "record_security_event"  # Always record, routing is for future extensions


# ─── Build the graph ──────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    graph = StateGraph(GraphState)

    graph.add_node("ingest_input", ingest_input)
    graph.add_node("scan_input", scan_input)
    graph.add_node("contextual_analysis", contextual_analysis)
    graph.add_node("correlate_session_risk", correlate_session_risk)
    graph.add_node("policy_gate", run_policy_gate)
    graph.add_node("record_security_event", record_security_event)

    graph.set_entry_point("ingest_input")
    graph.add_edge("ingest_input", "scan_input")
    graph.add_edge("scan_input", "contextual_analysis")
    graph.add_edge("contextual_analysis", "correlate_session_risk")
    graph.add_edge("correlate_session_risk", "policy_gate")
    graph.add_edge("policy_gate", "record_security_event")
    graph.add_edge("record_security_event", END)

    return graph


# ─── Compiled graph (singleton) ───────────────────────────────────────────────

_compiled_graph = build_graph().compile()


async def run_security_pipeline(request: AnalyzeRequest) -> GraphState:
    """
    Execute the full security pipeline for a given analyze request.
    Returns the final GraphState with all findings populated.
    """
    initial_state = GraphState(
        request_id=str(uuid.uuid4()),
        session_id=request.session_id,
        text=request.text,
        source_type=request.source_type,
        scenario_id=request.scenario_id,
        start_time=time.monotonic(),
    )

    try:
        final_state = await _compiled_graph.ainvoke(initial_state)
        return GraphState(**final_state) if isinstance(final_state, dict) else final_state
    except Exception as exc:
        logger.error("Pipeline execution error: %s", exc)
        initial_state.error = str(exc)
        return initial_state
