import React, { useEffect, useState } from 'react';
import type { HealthResponse } from '../types/api';
import { getHealth } from '../services/api';
import { StatusDot, ModeBadge, Spinner } from '../components/ui/Badges';

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

  useEffect(() => { load(); }, []);

  const componentLabels: Record<string, { name: string; desc: string }> = {
    groq_llm: { name: 'Groq LLM', desc: 'Powers contextual analysis (Layer 2). Set GROQ_API_KEY to enable.' },
    langsmith: { name: 'LangSmith', desc: 'Distributed trace observability. Set LANGSMITH_API_KEY and LANGSMITH_TRACING=true.' },
    chromadb: { name: 'ChromaDB', desc: 'Vector similarity for attack examples. Optional Layer 4 feature.' },
    database: { name: 'SQLite Database', desc: 'Persistent storage for security events and evaluation results.' },
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">System Health</h1>
          <p className="text-slate-400 text-sm">Component availability and current execution mode.</p>
        </div>
        <button onClick={load} className="btn-ghost flex items-center gap-2">
          {loading ? <Spinner className="w-4 h-4" /> : null}
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-cyber-red/10 border border-cyber-red/30 rounded-xl p-6 text-center">
          <div className="text-cyber-red font-bold mb-2">Backend Unavailable</div>
          <p className="text-slate-400 text-sm">
            Start the backend: <code className="font-mono bg-navy-900 px-2 py-0.5 rounded text-cyber-blue">
              cd backend && uvicorn app.main:app --reload --port 8000
            </code>
          </p>
        </div>
      )}

      {health && (
        <div className="space-y-4">
          {/* Overall Status */}
          <div className="card-cyber flex items-center gap-4">
            <div className={`w-12 h-12 rounded-full flex items-center justify-center text-2xl ${
              health.status === 'healthy' ? 'bg-cyber-green/20' : 'bg-cyber-amber/20'
            }`}>
              {health.status === 'healthy' ? '✓' : '⚠'}
            </div>
            <div>
              <div className="font-bold text-white capitalize">{health.status}</div>
              <div className="text-slate-400 text-sm">
                Last checked: {new Date(health.timestamp).toLocaleString()}
              </div>
            </div>
            <div className="ml-auto">
              <ModeBadge mode={health.execution_mode} />
            </div>
          </div>

          {/* Component Cards */}
          <div className="grid md:grid-cols-2 gap-4">
            {health.components.map(c => {
              const meta = componentLabels[c.name] ?? { name: c.name, desc: '' };
              return (
                <div key={c.name} className="card">
                  <div className="flex items-center gap-3 mb-2">
                    <StatusDot status={c.available ? 'healthy' : 'error'} />
                    <h3 className="font-semibold text-white">{meta.name}</h3>
                    <span className={`ml-auto text-xs font-semibold ${c.available ? 'text-cyber-green' : 'text-cyber-red'}`}>
                      {c.available ? 'AVAILABLE' : 'UNAVAILABLE'}
                    </span>
                  </div>
                  <p className="text-slate-400 text-xs mb-2">{meta.desc}</p>
                  <div className="text-xs font-mono bg-navy-900 px-2 py-1 rounded text-slate-400">
                    {c.detail}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Execution Mode Explanation */}
          <div className="card border-l-2 border-cyber-blue/40">
            <h2 className="font-semibold text-white mb-3">Execution Mode: {health.execution_mode}</h2>
            {health.execution_mode === 'FULL' ? (
              <p className="text-slate-300 text-sm">
                All components are available. Groq LLM provides contextual analysis alongside the deterministic scanner and policy gate.
              </p>
            ) : health.execution_mode === 'DEGRADED' ? (
              <p className="text-slate-300 text-sm">
                Some components are unavailable. Core security functions (scanner + policy gate) remain operational with reduced accuracy.
              </p>
            ) : (
              <p className="text-slate-300 text-sm">
                <strong>LOCAL_BASELINE mode:</strong> Groq is not configured. Only deterministic pattern matching and the policy gate are active.
                The system will correctly detect many common attacks but lacks LLM-based contextual reasoning.
                Set GROQ_API_KEY to enable full mode.
              </p>
            )}
          </div>
        </div>
      )}

      {/* Configuration Guide */}
      <div className="card">
        <h2 className="font-semibold text-white mb-4">Configuration</h2>
        <div className="code-block space-y-1">
          <div><span className="text-slate-500"># Backend: backend/.env</span></div>
          <div><span className="text-cyber-cyan">GROQ_API_KEY</span>=<span className="text-cyber-amber">your-key-here</span></div>
          <div><span className="text-cyber-cyan">GROQ_MODEL</span>=<span className="text-cyber-amber">llama-3.1-8b-instant</span></div>
          <div><span className="text-cyber-cyan">LANGSMITH_TRACING</span>=<span className="text-cyber-amber">true</span> <span className="text-slate-500"># optional</span></div>
          <div><span className="text-cyber-cyan">LANGSMITH_API_KEY</span>=<span className="text-cyber-amber">your-langsmith-key</span></div>
          <div className="mt-2"><span className="text-slate-500"># Frontend: frontend/.env</span></div>
          <div><span className="text-cyber-cyan">VITE_API_BASE_URL</span>=<span className="text-cyber-amber">http://localhost:8000</span></div>
        </div>
      </div>
    </div>
  );
};
