import axios from 'axios';
import type {
  AnalyzeRequest,
  AnalyzeResponse,
  EvaluationResult,
  EventListResponse,
  HealthResponse,
  SecurityEvent,
} from '../types/api';

// Use Vite proxy — /api routes are proxied to backend
const BASE_URL = import.meta.env.VITE_API_BASE_URL
  ? `${import.meta.env.VITE_API_BASE_URL}/api/v1`
  : '/api/v1';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
});

// ─── Health ───────────────────────────────────────────────────────────────────

export const getHealth = (): Promise<HealthResponse> =>
  api.get<HealthResponse>('/health').then(r => r.data);

// ─── Analysis ─────────────────────────────────────────────────────────────────

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

// ─── Tools ───────────────────────────────────────────────────────────────────

export const simulateTool = (tool_name: string, parameters: Record<string, unknown> = {}) =>
  api.post('/tools/simulate', { tool_name, parameters }).then(r => r.data);

// ─── Evaluation ───────────────────────────────────────────────────────────────

export const runEvaluation = (max_examples?: number): Promise<EvaluationResult> =>
  api.post<EvaluationResult>('/evaluate', { max_examples }).then(r => r.data);

export const getEvaluationResults = (): Promise<EvaluationResult> =>
  api.get<EvaluationResult>('/evaluate/results').then(r => r.data);
