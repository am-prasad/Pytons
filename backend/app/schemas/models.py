"""
AgentShield Pydantic Schemas
Strictly validated request/response models for all AgentShield endpoints.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator


# ─── Enums ────────────────────────────────────────────────────────────────────

class SourceType(str, Enum):
    USER_PROMPT = "user_prompt"
    RETRIEVED_DOCUMENT = "retrieved_document"
    WEB_CONTENT = "web_content"
    TOOL_OUTPUT = "tool_output"
    CONVERSATION_HISTORY = "conversation_history"


class RiskCategory(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class AttackType(str, Enum):
    NONE = "none"
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    TOOL_MANIPULATION = "tool_manipulation"
    MULTI_TURN = "multi_turn"
    SECRET_EXFILTRATION = "secret_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    POLICY_BYPASS = "policy_bypass"
    AMBIGUOUS = "ambiguous"


class ExecutionMode(str, Enum):
    FULL = "FULL"
    DEGRADED = "DEGRADED"
    LOCAL_BASELINE = "LOCAL_BASELINE"


class NodeStatus(str, Enum):
    RAN = "ran"
    SKIPPED = "skipped"
    ERROR = "error"
    FALLBACK = "fallback"


# ─── Shared building blocks ────────────────────────────────────────────────────

class EvidenceSnippet(BaseModel):
    text: str
    indicator: str
    layer: str  # e.g. "scanner", "contextual", "session", "document"
    chunk_index: Optional[int] = None
    page: Optional[int] = None


class WorkflowNode(BaseModel):
    name: str
    status: NodeStatus
    duration_ms: Optional[float] = None
    detail: Optional[str] = None


class TraceEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    status: str
    duration_ms: Optional[float] = None
    detail: Optional[str] = None


# ─── Analysis Request / Response ──────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000)
    source_type: SourceType = SourceType.USER_PROMPT
    session_id: Optional[str] = Field(default=None, max_length=64)
    scenario_id: Optional[str] = Field(default=None, max_length=64)

    @field_validator("text")
    @classmethod
    def strip_text(cls, v: str) -> str:
        return v.strip()


class ScannerFindings(BaseModel):
    indicators_found: List[str] = []
    patterns_matched: List[str] = []
    raw_score: float = 0.0


class ContextualFindings(BaseModel):
    attack_category: AttackType = AttackType.NONE
    confidence: float = 0.0
    evidence: List[EvidenceSnippet] = []
    recommended_action: PolicyDecision = PolicyDecision.ALLOW
    provider: str = "none"  # "groq", "local_heuristic", "none"
    model_id: Optional[str] = None
    note: Optional[str] = None
    cached: bool = False


class SessionCorrelation(BaseModel):
    session_id: Optional[str] = None
    prior_risk_events: int = 0
    probing_count: int = 0
    escalation_detected: bool = False
    session_risk_boost: float = 0.0
    contributing_events: List[str] = []
    crescendo_reason: Optional[str] = None


class PolicyResult(BaseModel):
    decision: PolicyDecision
    risk_score: float = Field(ge=0, le=100)
    risk_category: RiskCategory
    explanation: str
    blocked_reason: Optional[str] = None


class ToolActionResult(BaseModel):
    tool_name: Optional[str] = None
    proposed_action: Optional[str] = None
    authorized: bool = False
    policy_gate_result: PolicyDecision = PolicyDecision.ALLOW
    executed: bool = False
    result: Optional[str] = None
    explanation: str = ""


class AnalyzeResponse(BaseModel):
    request_id: str
    timestamp: datetime
    source_type: SourceType
    session_id: Optional[str] = None
    risk_score: float
    risk_category: RiskCategory
    policy_decision: PolicyDecision
    attack_types: List[AttackType]
    evidence: List[EvidenceSnippet]
    scanner_findings: ScannerFindings
    contextual_findings: ContextualFindings
    session_correlation: SessionCorrelation
    policy_result: PolicyResult
    tool_action: Optional[ToolActionResult] = None
    workflow_nodes: List[WorkflowNode]
    trace_events: List[TraceEvent]
    latency_ms: float
    execution_mode: ExecutionMode
    langsmith_trace_id: Optional[str] = None
    langsmith_trace_url: Optional[str] = None


# ─── Document Upload & Inspection Models ───────────────────────────────────────

class DocumentChunk(BaseModel):
    page: int
    chunk_index: int
    char_start: int
    char_end: int
    text_preview: str
    obfuscation_flags: List[str] = []
    scanner_score: float = 0.0
    scanner_patterns: List[str] = []
    sent_to_llm: bool = False
    decision: PolicyDecision = PolicyDecision.ALLOW
    judge_finding: Optional[ContextualFindings] = None


class DocumentMetadata(BaseModel):
    filename: str
    file_type: str  # "pdf" or "txt"
    file_size_bytes: int
    pages: int
    extracted_chars: int
    chunks_total: int
    chunks_scanned: int
    chunks_sent_to_llm: int
    llm_review_status: str  # "complete", "partial", "skipped", "failed"
    limitation_note: Optional[str] = None
    suspicious_regions: List[str] = []


class AgentExecutionResult(BaseModel):
    mode: str  # "protected" | "unprotected"
    model: str
    answer: str
    proposed_actions: List[Dict[str, Any]] = []
    authorizations: List[Dict[str, Any]] = []
    executed_actions: List[Dict[str, Any]] = []
    denied_actions: List[Dict[str, Any]] = []
    notices: List[str] = []
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None


class DocumentAnalyzeResponse(BaseModel):
    request_id: str
    timestamp: datetime
    doc_meta: DocumentMetadata
    task: str
    risk_score: float
    risk_category: RiskCategory
    policy_decision: PolicyDecision
    attack_types: List[AttackType]
    evidence: List[EvidenceSnippet]
    chunks: List[DocumentChunk]
    unprotected_agent: AgentExecutionResult
    protected_agent: AgentExecutionResult
    workflow_nodes: List[WorkflowNode]
    trace_events: List[TraceEvent]
    alerts: List[Dict[str, Any]] = []
    latency_ms: float
    execution_mode: ExecutionMode
    judge_model: str
    agent_model: str
    langsmith_trace_id: Optional[str] = None
    langsmith_trace_url: Optional[str] = None
    json_report: Dict[str, Any] = {}


# ─── Alerting & Approvals ──────────────────────────────────────────────────────

class AlertEvent(BaseModel):
    alert_id: str
    timestamp: datetime
    severity: RiskCategory
    checkpoint: str
    source_ref: str
    evidence: List[str] = []
    blocked_action: Optional[str] = None
    recommendation: str
    user_notice: str
    status: str = "delivered"  # "delivered", "pending", "approved", "rejected"


class ApprovalRequest(BaseModel):
    approval_id: str
    timestamp: datetime
    tool_name: str
    parameters: Dict[str, Any] = {}
    session_id: Optional[str] = None
    risk_score: float = 0.0
    reason: str = ""
    status: str = "PENDING"  # "PENDING", "APPROVED", "REJECTED"


class ApprovalDecision(BaseModel):
    approval_id: str
    decision: str  # "APPROVE" or "REJECT"
    reviewer: Optional[str] = "admin"


class ApprovalListResponse(BaseModel):
    approvals: List[ApprovalRequest]
    total: int


# ─── Tool Simulation ──────────────────────────────────────────────────────────

ALLOWED_TOOL_NAMES = {
    "get_public_status",
    "search_demo_documents",
    "read_inbox",
    "send_email",
    "request_sensitive_export",
}


class ToolSimulateRequest(BaseModel):
    tool_name: str
    parameters: Dict[str, Any] = {}
    session_id: Optional[str] = None

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        if v not in ALLOWED_TOOL_NAMES:
            raise ValueError(f"Tool '{v}' is not in the allowlist: {ALLOWED_TOOL_NAMES}")
        return v


class ToolSimulateResponse(BaseModel):
    tool_name: str
    executed: bool
    authorized: bool
    policy_decision: PolicyDecision
    result: Optional[str]
    explanation: str
    latency_ms: float


# ─── Session ──────────────────────────────────────────────────────────────────

class SessionResetRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=64)


class SessionResetResponse(BaseModel):
    session_id: str
    cleared: bool
    message: str


# ─── Security Events ──────────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    event_id: str
    request_id: str
    session_id: Optional[str] = None
    timestamp: datetime
    source_type: str
    risk_score: float
    risk_category: str
    policy_decision: str
    attack_types: List[str]
    execution_mode: str
    latency_ms: float
    summary: str


class EventListResponse(BaseModel):
    events: List[SecurityEvent]
    total: int
    page: int
    page_size: int


# ─── Evaluation ───────────────────────────────────────────────────────────────

class EvaluationRunRequest(BaseModel):
    dataset_path: Optional[str] = None
    max_examples: Optional[int] = Field(default=None, ge=1, le=500)


class CategoryMetrics(BaseModel):
    label: str
    total: int
    correct: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None


class EvaluationResult(BaseModel):
    run_id: str
    timestamp: datetime
    total_examples: int
    attack_recall: float
    precision: float
    false_positive_rate: float
    block_rate_on_dangerous: float
    median_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    config_name: Optional[str] = "full_pipeline"
    category_metrics: List[CategoryMetrics]
    confusion_matrix: Dict[str, Dict[str, int]]
    execution_mode: ExecutionMode
    notes: str



# ─── Health ───────────────────────────────────────────────────────────────────

class ComponentStatus(BaseModel):
    name: str
    available: bool
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    execution_mode: ExecutionMode
    components: List[ComponentStatus]
    timestamp: datetime
    judge_model: Optional[str] = None
    agent_model: Optional[str] = None
    last_call_status: Optional[str] = None
    last_error_class: Optional[str] = None
