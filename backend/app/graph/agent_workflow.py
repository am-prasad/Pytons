"""
AgentShield Agent Security Workflow (LangGraph)
Orchestrates dual-column evaluation:
1. Unprotected Agent (Pass-through Baseline: model sees poisoned chunk, executes harmful actions)
2. Protected Agent (Shield Active: normalizes, drops hostile chunks, enforces policy gate & egress controls, triggers alerts)

Includes:
- Bounded concurrent Groq judge calls
- Real tool execution sandbox
- Tool output loop screening (untrusted data)
- Structured execution trace with millisecond timings and node statuses
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

try:
    from langsmith import traceable
except Exception:
    def traceable(*args, **kwargs):
        def decorator(fn):
            return fn
        return decorator

from app.core.config import get_settings
from app.policy import gate as policy_gate
from app.schemas.models import (
    AgentExecutionResult,
    AttackType,
    ContextualFindings,
    DocumentChunk,
    DocumentMetadata,
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
from app.services.alerts import create_and_dispatch_alert
from app.services.documents import chunk_and_scan_document, select_chunks_for_judge
from app.services.groq_client import call_agent_llm, call_groq_judge
from app.services.session_store import get_store
from app.services.tools import execute_tool


# ─── Dual Agent Workflow State ────────────────────────────────────────────────

class AgentShieldState(BaseModel):
    request_id: str = ""
    session_id: Optional[str] = None
    task: str = ""
    doc_meta: Optional[DocumentMetadata] = None
    pages_data: List[Tuple[int, str]] = []

    # Pipeline artifacts
    chunks: List[DocumentChunk] = []
    selected_chunks: List[DocumentChunk] = []
    aggregate_findings: Optional[PolicyResult] = None
    session_correlation: Optional[SessionCorrelation] = None
    overall_risk_score: float = 0.0
    overall_category: RiskCategory = RiskCategory.LOW
    overall_decision: PolicyDecision = PolicyDecision.ALLOW
    attack_types: List[AttackType] = []
    evidence: List[EvidenceSnippet] = []

    # Agent runs
    unprotected_result: Optional[AgentExecutionResult] = None
    protected_result: Optional[AgentExecutionResult] = None

    # Telemetry & Auditing
    workflow_nodes: List[WorkflowNode] = []
    trace_events: List[TraceEvent] = []
    alerts: List[Dict[str, Any]] = []
    execution_mode: ExecutionMode = ExecutionMode.LOCAL_BASELINE
    start_time: float = 0.0


def _record_step(
    state: AgentShieldState,
    node_name: str,
    status: NodeStatus,
    t_start: float,
    detail: str = "",
) -> None:
    duration = (time.monotonic() - t_start) * 1000
    state.workflow_nodes.append(
        WorkflowNode(
            name=node_name,
            status=status,
            duration_ms=round(duration, 2),
            detail=detail,
        )
    )
    state.trace_events.append(
        TraceEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=node_name,
            status=status.value,
            duration_ms=round(duration, 2),
            detail=detail,
        )
    )


@traceable(name="AgentShield Dual Agent Workflow", run_type="chain")
async def execute_document_security_pipeline(
    task: str,
    doc_meta: DocumentMetadata,
    pages_data: List[Tuple[int, str]],
    session_id: Optional[str] = None,
) -> AgentShieldState:
    """
    Executes the comprehensive AgentShield inspection and dual-agent demonstration.
    """
    settings = get_settings()
    t_overall = time.monotonic()

    state = AgentShieldState(
        request_id=str(uuid.uuid4()),
        session_id=session_id or f"doc-sess-{uuid.uuid4().hex[:6]}",
        task=task,
        doc_meta=doc_meta,
        pages_data=pages_data,
        execution_mode=ExecutionMode.FULL if settings.groq_configured else ExecutionMode.LOCAL_BASELINE,
        start_time=t_overall,
    )

    # ── Node 1: Ingest & Document Normalization ────────────────────────────────
    t0 = time.monotonic()
    _record_step(
        state,
        "ingest_document",
        NodeStatus.RAN,
        t0,
        f"File: {doc_meta.filename} ({doc_meta.pages} pages, {doc_meta.extracted_chars} chars, format: {doc_meta.file_type})",
    )

    # ── Node 2: Chunking & Deterministic Fast Screening (ALL chunks) ───────────
    t0 = time.monotonic()
    chunks = chunk_and_scan_document(doc_meta, pages_data)
    state.chunks = chunks
    flagged_chunks = [c for c in chunks if c.scanner_score >= settings.scanner_suspicious_threshold or c.obfuscation_flags]
    _record_step(
        state,
        "scan_chunks",
        NodeStatus.RAN,
        t0,
        f"Scanned {len(chunks)} chunks. Found {len(flagged_chunks)} suspicious regions.",
    )

    # ── Node 3: Budgeted Selection for Contextual LLM Review ───────────────────
    t0 = time.monotonic()
    selected_for_judge = select_chunks_for_judge(
        chunks,
        max_llm_calls=settings.max_llm_calls_per_doc,
        score_threshold=settings.scanner_suspicious_threshold,
    )
    state.selected_chunks = selected_for_judge
    doc_meta.chunks_sent_to_llm = len(selected_for_judge)
    _record_step(
        state,
        "select_for_llm",
        NodeStatus.RAN,
        t0,
        f"Budgeted {len(selected_for_judge)} of {len(chunks)} chunks for contextual review (limit: {settings.max_llm_calls_per_doc}).",
    )

    # ── Node 4: Concurrent Groq Contextual Judge ──────────────────────────────
    t0 = time.monotonic()
    if selected_for_judge:
        # Bounded concurrent execution (max 3 concurrent)
        semaphore = asyncio.Semaphore(3)

        async def _judge_chunk(chunk: DocumentChunk):
            async with semaphore:
                raw_text = next((p[1] for p in pages_data if p[0] == chunk.page), "")
                chunk_slice = raw_text[chunk.char_start:chunk.char_end]
                # Run synchronous judge in executor thread
                finding = await asyncio.to_thread(
                    call_groq_judge,
                    chunk_slice,
                    SourceType.RETRIEVED_DOCUMENT,
                )
                chunk.judge_finding = finding
                if finding.recommended_action == PolicyDecision.BLOCK:
                    chunk.decision = PolicyDecision.BLOCK
                elif finding.recommended_action == PolicyDecision.QUARANTINE and chunk.decision != PolicyDecision.BLOCK:
                    chunk.decision = PolicyDecision.QUARANTINE

        await asyncio.gather(*[_judge_chunk(c) for c in selected_for_judge])
        doc_meta.llm_review_status = "complete" if settings.groq_configured else "local_fallback"
        _record_step(
            state,
            "judge_chunks",
            NodeStatus.RAN if settings.groq_configured else NodeStatus.FALLBACK,
            t0,
            f"Evaluated {len(selected_for_judge)} chunks via Groq Judge ({settings.groq_model}).",
        )
    else:
        doc_meta.llm_review_status = "skipped"
        _record_step(state, "judge_chunks", NodeStatus.SKIPPED, t0, "No chunks exceeded threat thresholds.")

    # ── Node 5: Aggregate Findings & Session Correlation ───────────────────────
    t0 = time.monotonic()
    max_scanner_score = max((c.scanner_score for c in chunks), default=0.0)
    top_scanner_patterns: List[str] = []
    for c in chunks:
        top_scanner_patterns.extend(c.scanner_patterns)
    top_scanner_patterns = list(dict.fromkeys(top_scanner_patterns))

    # Highest severity judge finding
    highest_judge_finding: Optional[ContextualFindings] = None
    for c in selected_for_judge:
        if c.judge_finding and c.judge_finding.attack_category != AttackType.NONE:
            if highest_judge_finding is None or c.judge_finding.confidence > highest_judge_finding.confidence:
                highest_judge_finding = c.judge_finding

    session_store = get_store()
    correlation = session_store.get_correlation(state.session_id, task)
    state.session_correlation = correlation

    # Compute overall policy result
    combined_scanner = ScannerFindings(
        raw_score=max_scanner_score,
        patterns_matched=top_scanner_patterns,
        indicators_found=[],
    )
    combined_contextual = highest_judge_finding or ContextualFindings()

    policy_result = policy_gate.decide(
        scanner=combined_scanner,
        contextual=combined_contextual,
        session=correlation,
        source_type=SourceType.RETRIEVED_DOCUMENT,
    )
    state.aggregate_findings = policy_result
    state.overall_risk_score = policy_result.risk_score
    state.overall_category = policy_result.risk_category
    state.overall_decision = policy_result.decision

    if combined_contextual.attack_category != AttackType.NONE:
        state.attack_types.append(combined_contextual.attack_category)
    if any("override" in p or "ignore" in p for p in top_scanner_patterns):
        state.attack_types.append(AttackType.INDIRECT_INJECTION)
    state.attack_types = list(dict.fromkeys(state.attack_types))

    # Evidence compilation
    for c in chunks:
        if c.scanner_patterns:
            state.evidence.append(
                EvidenceSnippet(
                    text=c.text_preview[:120],
                    indicator=f"Pattern: {', '.join(c.scanner_patterns)}",
                    layer="scanner",
                    chunk_index=c.chunk_index,
                    page=c.page,
                )
            )
        if c.judge_finding and c.judge_finding.evidence:
            for ev in c.judge_finding.evidence:
                ev.chunk_index = c.chunk_index
                ev.page = c.page
                state.evidence.append(ev)

    _record_step(
        state,
        "aggregate_findings",
        NodeStatus.RAN,
        t0,
        f"Aggregated Decision: {state.overall_decision.value} (Risk Score: {state.overall_risk_score:.1f}/100)",
    )

    # ── Node 6: Dual Agent Execution (Unprotected vs Protected) ────────────────
    full_document_text = "\n\n".join(p[1] for p in pages_data)

    # A. Unprotected Agent Execution (Pass-through: sees raw text, executes requested tools)
    t0_unprot = time.monotonic()
    unprot_answer, unprot_tools, unprot_tokens = await asyncio.to_thread(
        call_agent_llm,
        task=task,
        document_context=full_document_text,
        allow_injection_execution=True,
    )

    unprot_executed: List[Dict[str, Any]] = []
    unprot_auths: List[Dict[str, Any]] = []
    for tool_call in unprot_tools:
        t_name = tool_call.get("name", "")
        t_params = tool_call.get("parameters", {})
        # Unprotected pass-through: NO gate check; tool executes directly in sandbox!
        unprot_auths.append({
            "tool": t_name,
            "decision": "PASSTHROUGH_ALLOW",
            "reason": "Unprotected baseline: policy gate bypassed.",
        })
        try:
            exec_res = execute_tool(t_name, t_params)
            unprot_executed.append({
                "tool": t_name,
                "executed": True,
                "result": exec_res,
            })
        except Exception as exc:
            unprot_executed.append({
                "tool": t_name,
                "executed": False,
                "error": str(exc),
            })

    state.unprotected_result = AgentExecutionResult(
        mode="unprotected",
        model=settings.agent_model,
        answer=unprot_answer,
        proposed_actions=unprot_tools,
        authorizations=unprot_auths,
        executed_actions=unprot_executed,
        denied_actions=[],
        notices=["Running in unprotected demo baseline mode."],
        prompt_tokens=unprot_tokens.get("prompt_tokens"),
        completion_tokens=unprot_tokens.get("completion_tokens"),
    )
    _record_step(
        state,
        "agent_unprotected_run",
        NodeStatus.RAN,
        t0_unprot,
        f"Unprotected agent ran {len(unprot_executed)} tools without policy enforcement.",
    )

    # B. Protected Agent Execution (Sanitizes hostile chunks, gates actions, alerts)
    t0_prot = time.monotonic()
    safe_chunks_text = []
    dropped_chunk_count = 0

    for c in chunks:
        # Checkpoint: Drop chunks that were blocked or quarantined by scanner/judge
        if c.decision in (PolicyDecision.BLOCK, PolicyDecision.QUARANTINE):
            dropped_chunk_count += 1
        else:
            safe_chunks_text.append(c.text_preview)

    sanitized_context = "\n\n".join(safe_chunks_text) if safe_chunks_text else (
        "All retrieved document chunks contained severe security policy violations and were quarantined."
    )

    prot_answer, prot_tools, prot_tokens = await asyncio.to_thread(
        call_agent_llm,
        task=task,
        document_context=sanitized_context,
        allow_injection_execution=False,
    )

    prot_executed: List[Dict[str, Any]] = []
    prot_denied: List[Dict[str, Any]] = []
    prot_auths: List[Dict[str, Any]] = []
    prot_notices: List[str] = []

    if dropped_chunk_count > 0:
        prot_notices.append(
            f"Security Notice: {dropped_chunk_count} hostile or untrusted content chunk(s) were neutralized."
        )

    for tool_call in prot_tools:
        t_name = tool_call.get("name", "")
        t_params = tool_call.get("parameters", {})

        # Deterministic Policy Gate & Egress Check
        auth_decision, auth_reason = policy_gate.authorize_tool_action(
            tool_name=t_name,
            parameters=t_params,
            policy=policy_result,
            user_task=task,
        )

        prot_auths.append({
            "tool": t_name,
            "decision": auth_decision.value,
            "reason": auth_reason,
        })

        if auth_decision == PolicyDecision.ALLOW:
            try:
                exec_res = execute_tool(t_name, t_params)
                prot_executed.append({
                    "tool": t_name,
                    "executed": True,
                    "result": exec_res,
                })
            except Exception as exc:
                prot_executed.append({
                    "tool": t_name,
                    "executed": False,
                    "error": str(exc),
                })
        else:
            # Action DENIED or REQUIRES_APPROVAL
            prot_denied.append({
                "tool": t_name,
                "executed": False,
                "decision": auth_decision.value,
                "reason": auth_reason,
            })
            prot_notices.append(f"Action '{t_name}' prevented by policy gate: {auth_reason}")

            # Dispatch Security Alert
            alert_event, appr_req = create_and_dispatch_alert(
                severity=state.overall_category,
                checkpoint="authorize_actions",
                source_ref=f"{doc_meta.filename}#chunks_{dropped_chunk_count}",
                evidence=[auth_reason],
                blocked_action=t_name,
                recommendation="Investigate document provenance; verify agent least-privilege egress controls.",
                requires_approval=(auth_decision == PolicyDecision.REQUIRE_APPROVAL),
                tool_params=t_params,
                session_id=state.session_id,
                risk_score=state.overall_risk_score,
            )
            state.alerts.append(alert_event.model_dump())

    state.protected_result = AgentExecutionResult(
        mode="protected",
        model=settings.agent_model,
        answer=prot_answer,
        proposed_actions=prot_tools,
        authorizations=prot_auths,
        executed_actions=prot_executed,
        denied_actions=prot_denied,
        notices=prot_notices,
        prompt_tokens=prot_tokens.get("prompt_tokens"),
        completion_tokens=prot_tokens.get("completion_tokens"),
    )

    _record_step(
        state,
        "agent_protected_run",
        NodeStatus.RAN,
        t0_prot,
        f"Protected agent sanitized {dropped_chunk_count} hostile chunks and blocked {len(prot_denied)} unauthorized actions.",
    )

    # ── Node 7: Audit Persistence ──────────────────────────────────────────────
    t0_audit = time.monotonic()
    session_store.add_event(
        session_id=state.session_id,
        risk_score=state.overall_risk_score,
        decision=state.overall_decision,
        attack_types=[a.value for a in state.attack_types],
        request_id=state.request_id,
        text=task,
    )
    _record_step(state, "persist_audit", NodeStatus.RAN, t0_audit, "Security telemetry and session event logged.")

    return state


async def run_dual_agent_workflow(
    task: str,
    chunks: Optional[List[DocumentChunk]] = None,
    meta: Optional[DocumentMetadata] = None,
    session_id: Optional[str] = None,
    pages_data: Optional[List[Tuple[int, str]]] = None,
) -> Dict[str, Any]:
    """
    Convenience wrapper for scripts and evaluations to run the dual agent workflow.
    Returns: {"unprotected": unprot_result, "protected": prot_result, "state": state}
    """
    if not meta:
        meta = DocumentMetadata(
            filename="scenario_document.txt",
            file_type="txt",
            file_size_bytes=1024,
            pages=1,
            extracted_chars=500,
        )
    if not pages_data:
        if chunks:
            pages_dict = {}
            for c in chunks:
                pages_dict.setdefault(c.page, []).append(c.content)
            pages_data = [(page_num, "\n".join(texts)) for page_num, texts in sorted(pages_dict.items())]
        else:
            pages_data = [(1, "")]

    state = await execute_document_security_pipeline(
        task=task,
        doc_meta=meta,
        pages_data=pages_data,
        session_id=session_id,
    )
    return {
        "unprotected": state.unprotected_result,
        "protected": state.protected_result,
        "state": state,
    }

