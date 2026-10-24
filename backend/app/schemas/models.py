"""
AgentShield Pydantic Schemas
All API request/response models with strict validation.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

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


# ─── Shared building blocks ────────────────────────────────────────────────────

class EvidenceSnippet(BaseModel):
    text: str
    indicator: str
    layer: str  # e.g. "scanner", "contextual", "session"


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


# ─── Analysis request / response ──────────────────────────────────────────────

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
    note: Optional[str] = None


class SessionCorrelation(BaseModel):
    session_id: Optional[str] = None
    prior_risk_events: int = 0
    escalation_detected: bool = False
    session_risk_boost: float = 0.0
    contributing_events: List[str] = []


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
    session_id: Optional[str]
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


# ─── Session ──────────────────────────────────────────────────────────────────

class SessionResetRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=64)


class SessionResetResponse(BaseModel):
    session_id: str
    cleared: bool
    message: str


# ─── Tool simulation ──────────────────────────────────────────────────────────

ALLOWED_TOOL_NAMES = {"get_public_status", "search_demo_documents", "request_sensitive_export"}


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


# ─── Events ───────────────────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    event_id: str
    request_id: str
    session_id: Optional[str]
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
    dataset_path: Optional[str] = None  # defaults to bundled dataset
    max_examples: Optional[int] = Field(default=None, ge=1, le=200)


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
    median_latency_ms: Optional[float]
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
