import React, { useEffect, useState } from 'react';
import type { HealthResponse } from '../types/api';
import { getHealth } from '../services/api';
import { StatusDot, ModeBadge, Spinner, ErrorBanner } from '../components/ui/Badges';

export const HealthPage: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(false);
    try {
      setHealth(await getHealth());
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const componentLabels: Record<string, { name: string; desc: string }> = {
    scanner: { name: 'Deterministic Scanner', desc: 'Fast regex-based pattern matching (Layer 1). Always active.' },
    groq_llm: { name: 'Groq LLM Contextual Judge', desc: 'Deep semantic classification (Layer 2). Requires GROQ_API_KEY.' },
    session_store: { name: 'Session Correlation Store', desc: 'Multi-turn drift detection (Layer 3). Tracks per-session risk escalation.' },
    policy_gate: { name: 'Deterministic Policy Gate', desc: 'Final security authority (Layer 4). Computes mathematical risk weights.' },
    database: { name: 'SQLite Persistence', desc: 'Local audit log storage for events and evaluation metrics.' },
    langsmith: { name: 'LangSmith Distributed Tracing', desc: 'Optional end-to-end trace collection and latency profiling.' },
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            System & Component Health
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Real-time status of pipeline detectors, LLM judge connectivity, and persistence layers.
          </p>
        </div>
        <button onClick={load} className="btn-ghost flex items-center gap-2">
          {loading && <Spinner className="w-3.5 h-3.5" />}
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <ErrorBanner message="Backend API is offline or unreachable. Run: uvicorn app.main:app --reload --port 8000" />
      )}

      {health && (
        <div className="space-y-4">
          {/* Status Header Card */}
          <div className="card flex items-center justify-between">
            <div className="flex items-center gap-3">
              <StatusDot status={health.status} />
              <div>
                <div className="font-semibold text-sm text-slate-900 dark:text-slate-100 capitalize">
                  System Status: {health.status}
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  Last verified: {new Date(health.timestamp).toLocaleTimeString()}
                </div>
              </div>
            </div>
            <div>
              <ModeBadge mode={health.execution_mode} />
            </div>
          </div>

          {/* Component Grid */}
          <div className="grid md:grid-cols-2 gap-4">
            {health.components.map(c => {
              const meta = componentLabels[c.name] ?? { name: c.name, desc: '' };
              return (
                <div key={c.name} className="card space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <StatusDot status={c.available ? 'healthy' : 'error'} />
                      <h3 className="font-semibold text-xs text-slate-900 dark:text-slate-100">
                        {meta.name}
                      </h3>
                    </div>
                    <span className={`text-[10px] font-mono font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded ${
                      c.available
                        ? 'bg-emerald-50 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300'
                        : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
                    }`}>
                      {c.available ? 'Ready' : 'Not Active'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                    {meta.desc}
                  </p>

                  <div className="font-mono text-[11px] p-2 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300">
                    {c.detail}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Operational Mode Policy */}
          <div className="card border-l-3 border-slate-400 dark:border-slate-600">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-2">
              Operational Mode Architecture
            </h2>
            {health.execution_mode === 'FULL' ? (
              <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                Operating in <strong>FULL</strong> mode. The Groq LLM contextual judge is active and provides semantic intent analysis. The deterministic policy gate combines LLM signals with the fast scanner and session correlation.
              </p>
            ) : (
              <div className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                <p>
                  Operating in <strong>LOCAL_BASELINE</strong> mode. The deterministic scanner, session correlation, and policy gate are fully functional without external API keys.
                </p>
                <p className="text-slate-500 dark:text-slate-400">
                  To activate Layer 2 Groq contextual reasoning, add your API key in <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 py-0.5 rounded">backend/.env</code>:
                  <code className="block mt-1 font-mono text-[11px] bg-slate-100 dark:bg-slate-800 p-2 rounded">
                    GROQ_API_KEY=your_groq_api_key_here
                  </code>
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
