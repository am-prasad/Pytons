// AgentShield API Types — mirrors the backend Pydantic schemas

export type SourceType =
  | 'user_prompt'
  | 'retrieved_document'
  | 'web_content'
  | 'tool_output'
  | 'conversation_history';

export type RiskCategory = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type PolicyDecision = 'ALLOW' | 'QUARANTINE' | 'BLOCK';
export type AttackType =
  | 'none'
  | 'direct_injection'
  | 'indirect_injection'
  | 'tool_manipulation'
  | 'multi_turn'
  | 'secret_exfiltration'
  | 'privilege_escalation'
  | 'policy_bypass'
  | 'ambiguous';
export type ExecutionMode = 'FULL' | 'DEGRADED' | 'LOCAL_BASELINE';
export type NodeStatus = 'ran' | 'skipped' | 'error';

export interface EvidenceSnippet {
  text: string;
  indicator: string;
  layer: string;
}

export interface WorkflowNode {
  name: string;
  status: NodeStatus;
  duration_ms?: number;
  detail?: string;
}

export interface TraceEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  status: string;
  duration_ms?: number;
  detail?: string;
}

export interface ScannerFindings {
  indicators_found: string[];
  patterns_matched: string[];
  raw_score: number;
}

export interface ContextualFindings {
  attack_category: AttackType;
  confidence: number;
  evidence: EvidenceSnippet[];
  recommended_action: PolicyDecision;
  provider: string;
  note?: string;
}

export interface SessionCorrelation {
  session_id?: string;
  prior_risk_events: number;
  escalation_detected: boolean;
  session_risk_boost: number;
  contributing_events: string[];
}

export interface PolicyResult {
  decision: PolicyDecision;
  risk_score: number;
  risk_category: RiskCategory;
  explanation: string;
  blocked_reason?: string;
}

export interface ToolActionResult {
  tool_name?: string;
  proposed_action?: string;
  authorized: boolean;
  policy_gate_result: PolicyDecision;
  executed: boolean;
  result?: string;
  explanation: string;
}

export interface AnalyzeRequest {
  text: string;
  source_type: SourceType;
  session_id?: string;
  scenario_id?: string;
}

export interface AnalyzeResponse {
  request_id: string;
  timestamp: string;
  source_type: SourceType;
  session_id?: string;
  risk_score: number;
  risk_category: RiskCategory;
  policy_decision: PolicyDecision;
  attack_types: AttackType[];
  evidence: EvidenceSnippet[];
  scanner_findings: ScannerFindings;
  contextual_findings: ContextualFindings;
  session_correlation: SessionCorrelation;
  policy_result: PolicyResult;
  tool_action?: ToolActionResult;
  workflow_nodes: WorkflowNode[];
  trace_events: TraceEvent[];
  latency_ms: number;
  execution_mode: ExecutionMode;
  langsmith_trace_id?: string;
}

export interface ComponentStatus {
  name: string;
  available: boolean;
  detail?: string;
}

export interface HealthResponse {
  status: string;
  execution_mode: ExecutionMode;
  components: ComponentStatus[];
  timestamp: string;
}

export interface SecurityEvent {
  event_id: string;
  request_id: string;
  session_id?: string;
  timestamp: string;
  source_type: string;
  risk_score: number;
  risk_category: string;
  policy_decision: string;
  attack_types: string[];
  execution_mode: string;
  latency_ms: number;
  summary: string;
}

export interface EventListResponse {
  events: SecurityEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface CategoryMetrics {
  label: string;
  total: number;
  correct: number;
  precision?: number;
  recall?: number;
  f1?: number;
}

export interface EvaluationResult {
  run_id: string;
  timestamp: string;
  total_examples: number;
  attack_recall: number;
  precision: number;
  false_positive_rate: number;
  block_rate_on_dangerous: number;
  median_latency_ms?: number;
  category_metrics: CategoryMetrics[];
  confusion_matrix: Record<string, Record<string, number>>;
  execution_mode: ExecutionMode;
  notes: string;
}

// Attack Scenario presets
export interface AttackScenario {
  id: string;
  name: string;
  description: string;
  text: string;
  source_type: SourceType;
  category: string;
  expectedDecision: PolicyDecision;
}
