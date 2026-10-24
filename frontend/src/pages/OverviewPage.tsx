import React, { useEffect, useState } from 'react';
import type { HealthResponse, SecurityEvent, EventListResponse } from '../types/api';
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
      <div>
        <h1 className="text-2xl font-bold text-white mb-1">Overview</h1>
        <p className="text-slate-400 text-sm">AgentShield security pipeline status and recent activity.</p>
      </div>

      {backendDown && (
        <div className="bg-cyber-red/10 border border-cyber-red/30 rounded-xl p-4 text-cyber-red">
          <strong>Backend Unavailable</strong>
          <p className="text-sm mt-1 text-cyber-red/80">
            Could not reach the AgentShield API. Start the backend with: <code className="font-mono bg-navy-900 px-1 rounded">uvicorn app.main:app --reload</code>
          </p>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <InfoCard label="Total Analyzed" value={total} sub="All time" />
        <InfoCard label="Blocked" value={blocked} color="text-cyber-red" sub="From latest 10" />
        <InfoCard label="Quarantined" value={quarantined} color="text-cyber-amber" sub="From latest 10" />
        <InfoCard
          label="Execution Mode"
          value={health?.execution_mode ?? '—'}
          color={health?.execution_mode === 'FULL' ? 'text-cyber-green' : 'text-cyber-amber'}
          sub={health?.execution_mode === 'FULL' ? 'Groq + heuristics' : 'Local heuristics only'}
        />
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {/* System Health */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-white">System Health</h2>
            {health && <ModeBadge mode={health.execution_mode} />}
          </div>
          {loading ? (
            <div className="text-slate-500 text-sm">Loading...</div>
          ) : health ? (
            <div className="space-y-3">
              {health.components.map(c => (
                <div key={c.name} className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <StatusDot status={c.available ? 'healthy' : 'error'} />
                    <span className="text-sm text-slate-200 capitalize">{c.name.replace(/_/g, ' ')}</span>
                  </div>
                  <span className="text-xs text-slate-400 text-right max-w-40 truncate">{c.detail}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-slate-500 text-sm">Unavailable</div>
          )}
        </div>

        {/* Recent Events */}
        <div className="card">
          <h2 className="font-semibold text-white mb-4">Recent Security Events</h2>
          {events && events.events.length > 0 ? (
            <div className="space-y-2">
              {events.events.slice(0, 8).map(e => (
                <div key={e.event_id} className="flex items-center gap-3 text-sm py-1.5 border-b border-navy-700 last:border-0">
                  <DecisionBadge decision={e.policy_decision as 'ALLOW' | 'QUARANTINE' | 'BLOCK'} />
                  <span className="text-slate-400 text-xs flex-shrink-0">{e.source_type.replace(/_/g, ' ')}</span>
                  <span className="text-slate-500 text-xs font-mono flex-shrink-0">{e.risk_score.toFixed(0)}/100</span>
                  <span className="text-slate-400 text-xs truncate">{new Date(e.timestamp).toLocaleTimeString()}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-slate-500 text-sm py-6 text-center">
              No events yet. Run an analysis in the Security Playground.
            </div>
          )}
        </div>
      </div>

      {/* Architecture Overview */}
      <div className="card-cyber">
        <h2 className="font-semibold text-white mb-4">Security Pipeline</h2>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {[
            { label: 'Untrusted Input', color: 'bg-slate-700' },
            { label: '→', color: '' },
            { label: 'Provenance & Normalize', color: 'bg-navy-700' },
            { label: '→', color: '' },
            { label: 'Fast Scanner', color: 'bg-cyber-blue/10 border border-cyber-blue/20' },
            { label: '→', color: '' },
            { label: 'Contextual Analysis', color: 'bg-purple-900/30 border border-purple-500/20' },
            { label: '→', color: '' },
            { label: 'Session Correlation', color: 'bg-navy-700' },
            { label: '→', color: '' },
            { label: ' Policy Gate', color: 'bg-cyber-red/10 border border-cyber-red/30 text-cyber-red font-bold' },
            { label: '→', color: '' },
            { label: 'Safe Response / Audit', color: 'bg-cyber-green/10 border border-cyber-green/20 text-cyber-green' },
          ].map((item, i) =>
            item.label === '→' ? (
              <span key={i} className="text-slate-500">→</span>
            ) : (
              <span key={i} className={`px-3 py-1.5 rounded-lg text-xs font-medium ${item.color}`}>
                {item.label}
              </span>
            )
          )}
        </div>
        <p className="text-slate-500 text-xs mt-4">
          
        </p>
      </div>
    </div>
  );
};
