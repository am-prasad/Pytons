import axios from 'axios';
import type {
  AlertEvent,
  AnalyzeRequest,
  AnalyzeResponse,
  ApprovalDecision,
  ApprovalListResponse,
  DocumentAnalyzeResponse,
  EvaluationResult,
  EventListResponse,
  HealthResponse,
  SecurityEvent,
} from '../types/api';

const BASE_URL = import.meta.env.VITE_API_BASE_URL
  ? `${import.meta.env.VITE_API_BASE_URL}/api/v1`
  : '/api/v1';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 90000,
});

// ─── Health ───────────────────────────────────────────────────────────────────

export const getHealth = (): Promise<HealthResponse> =>
  api.get<HealthResponse>('/health').then(r => r.data);

// ─── Document Upload & Dual Agent Inspection ──────────────────────────────────

export const analyzeDocument = (
  file: File,
  task: string,
  session_id?: string
): Promise<DocumentAnalyzeResponse> => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('task', task);
  if (session_id) {
    formData.append('session_id', session_id);
  }

  return api
    .post<DocumentAnalyzeResponse>('/documents/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    .then(r => r.data);
};

// ─── Prompt / Text Analysis ───────────────────────────────────────────────────

export const analyzeInput = (body: AnalyzeRequest): Promise<AnalyzeResponse> =>
  api.post<AnalyzeResponse>('/analyze', body).then(r => r.data);

// ─── Sessions ─────────────────────────────────────────────────────────────────

export const resetSession = (session_id: string) =>
  api.post('/sessions/reset', { session_id }).then(r => r.data);

// ─── Events ──────────────────────────────────────────────────────────────────

export const getEvents = (page = 1, page_size = 20): Promise<EventListResponse> =>
  api.get<EventListResponse>('/events', { params: { page, page_size } }).then(r => r.data);

export const getEvent = (event_id: string): Promise<SecurityEvent> =>
  api.get<SecurityEvent>(`/events/${event_id}`).then(r => r.data);

// ─── Tools & Sandbox ──────────────────────────────────────────────────────────

export const simulateTool = (tool_name: string, parameters: Record<string, unknown> = {}) =>
  api.post('/tools/simulate', { tool_name, parameters }).then(r => r.data);

export const getSandboxOutbox = (): Promise<{ outbox_emails: any[]; exports: any[] }> =>
  api.get('/sandbox/outbox').then(r => r.data);

// ─── Alerts & Approvals ───────────────────────────────────────────────────────

export const getAlerts = (): Promise<{ alerts: AlertEvent[] }> =>
  api.get('/alerts').then(r => r.data);

export const getApprovals = (): Promise<ApprovalListResponse> =>
  api.get<ApprovalListResponse>('/approvals').then(r => r.data);

export const resolveApproval = (
  approval_id: string,
  decision: 'APPROVE' | 'REJECT'
): Promise<any> =>
  api.post('/approvals/resolve', { approval_id, decision }).then(r => r.data);

// ─── Evaluation Lab ───────────────────────────────────────────────────────────

export const runEvaluation = (max_examples?: number): Promise<EvaluationResult> =>
  api.post<EvaluationResult>('/evaluate', { max_examples }).then(r => r.data);

export const getEvaluationResults = (): Promise<EvaluationResult> =>
  api.get<EvaluationResult>('/evaluate/results').then(r => r.data);
