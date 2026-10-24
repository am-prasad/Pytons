import React, { useEffect, useState } from 'react';
import type { HealthResponse, EventListResponse } from '../types/api';
import { getHealth, getEvents } from '../services/api';
import { StatusDot, DecisionBadge, ModeBadge, InfoCard } from '../components/ui/Badges';

export const OverviewPage: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [events, setEvents] = useState<EventListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [backendDown, setBackendDown] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const [h, e] = await Promise.all([getHealth(), getEvents(1, 10)]);
        setHealth(h);
        setEvents(e);
        setBackendDown(false);
      } catch {
        setBackendDown(true);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const blocked = events?.events.filter(e => e.policy_decision === 'BLOCK').length ?? 0;
  const quarantined = events?.events.filter(e => e.policy_decision === 'QUARANTINE').length ?? 0;
  const total = events?.total ?? 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Security Overview
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Real-time prompt injection detection, action policy status, and telemetry.
        </p>
      </div>

      {backendDown && (
        <div className="rounded-md border border-rose-200 bg-rose-50 p-4 text-xs text-rose-800 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300">
          <div className="font-semibold mb-1">Backend Server Disconnected</div>
          <p>
            AgentShield API is unreachable at <code className="font-mono bg-white dark:bg-slate-900 px-1 py-0.5 rounded border border-rose-200 dark:border-rose-800">localhost:8000</code>.
            
          </p>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <InfoCard label="Total Requests" value={total} sub="Audited sessions" badge="Live" />
        <InfoCard label="Blocked Attacks" value={blocked} sub="Latest 10 window" />
        <InfoCard label="Quarantined" value={quarantined} sub="Held for review" />
        <InfoCard
          label="Execution Mode"
          value={health?.execution_mode ?? '—'}
          sub={health?.execution_mode === 'FULL' ? 'Groq LLM active' : 'Deterministic baseline'}
        />
      </div>

      {/* Two Column Layout: System Health & Event Activity */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Component Health */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Pipeline Component Status
            </h2>
            {health && <ModeBadge mode={health.execution_mode} />}
          </div>

          {loading ? (
            <div className="text-xs text-slate-400 py-4">Checking components...</div>
          ) : health ? (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {health.components.map(c => (
                <div key={c.name} className="py-2.5 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2.5">
                    <StatusDot status={c.available ? 'healthy' : 'error'} />
                    <span className="font-medium text-slate-800 dark:text-slate-200 capitalize">
                      {c.name.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-[200px]">
                    {c.detail}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-400 py-4">No telemetry available</div>
          )}
        </div>

        {/* Recent Audit Log */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Recent Security Events
            </h2>
            <span className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
              Audit log
            </span>
          </div>

          {events && events.events.length > 0 ? (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {events.events.slice(0, 7).map(e => (
                <div key={e.event_id} className="py-2 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2.5">
                    <DecisionBadge decision={e.policy_decision as 'ALLOW' | 'QUARANTINE' | 'BLOCK'} />
                    <span className="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                      {e.source_type.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      Score: {e.risk_score.toFixed(0)}
                    </span>
                    <span className="text-[11px] text-slate-400 dark:text-slate-500 font-mono">
                      {new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-400 py-8 text-center">
              No events recorded yet. Run tests in the Playground.
            </div>
          )}
        </div>
      </div>

      {/* Pipeline Interception Topology */}
      <div className="card">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">
          Architecture Interception Graph
        </h2>
        <p className="text-xs text-slate-600 dark:text-slate-400 mb-4 leading-relaxed">
          AgentShield inserts an autonomous security boundary at runtime. External content is tagged by provenance and evaluated before reaching the model or triggering tool actions.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {[
            { step: '01', name: 'Ingest & Tag', role: 'Provenance Isolation' },
            { step: '02', name: 'Fast Scanner', role: 'Rule Patterns (<5ms)' },
            { step: '03', name: 'Contextual Judge', role: 'Groq LLM / Heuristic' },
            { step: '04', name: 'Session Correlation', role: 'Multi-turn Drift' },
            { step: '05', name: 'Policy Gate', role: 'Deterministic Decision' },
            { step: '06', name: 'Tool Auth & Audit', role: 'Action Boundary' },
          ].map((item, idx) => (
            <div
              key={idx}
              className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/60 flex flex-col justify-between"
            >
              <div className="font-mono text-[10px] text-slate-400 dark:text-slate-500">
                {item.step}
              </div>
              <div className="font-medium text-xs text-slate-800 dark:text-slate-200 mt-2">
                {item.name}
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                {item.role}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
