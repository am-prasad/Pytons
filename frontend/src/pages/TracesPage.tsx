import React, { useEffect, useState } from 'react';
import type { SecurityEvent, EventListResponse } from '../types/api';
import { getEvents } from '../services/api';
import { DecisionBadge, StatusDot, EmptyState, Spinner } from '../components/ui/Badges';

export const TracesPage: React.FC = () => {
  const [data, setData] = useState<EventListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [error, setError] = useState(false);

  const load = async (page = 1) => {
    setLoading(true);
    try {
      const res = await getEvents(page, 20);
      setData(res);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white mb-1">Execution Traces</h1>
        <p className="text-slate-400 text-sm">Security audit trail for all analyzed inputs.</p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Event List */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-white">Security Events</h2>
            <button onClick={() => load()} className="btn-ghost text-xs py-1 px-3">Refresh</button>
          </div>

          {loading ? (
            <div className="flex justify-center py-12"><Spinner /></div>
          ) : error ? (
            <div className="text-cyber-red text-sm py-4">Failed to load events. Backend may be offline.</div>
          ) : data && data.events.length > 0 ? (
            <div className="space-y-1.5">
              {data.events.map(e => (
                <button
                  key={e.event_id}
                  onClick={() => setSelected(e)}
                  className={`w-full text-left px-3 py-3 rounded-lg border transition-all ${
                    selected?.event_id === e.event_id
                      ? 'border-cyber-blue/40 bg-cyber-blue/5'
                      : 'border-navy-700 hover:border-navy-600 bg-navy-900'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <DecisionBadge decision={e.policy_decision as 'ALLOW' | 'QUARANTINE' | 'BLOCK'} />
                    <span className="text-xs text-slate-400">{e.risk_category}</span>
                    <span className="text-xs font-mono text-slate-500">{e.risk_score.toFixed(0)}/100</span>
                    <span className="ml-auto text-xs text-slate-500">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="text-xs text-slate-300 truncate">{e.summary}</div>
                  <div className="flex gap-2 mt-1">
                    {e.attack_types.slice(0, 3).map(t => (
                      <span key={t} className="text-xs bg-navy-700 text-slate-400 px-1.5 py-0.5 rounded">
                        {t.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </button>
              ))}
              <div className="text-xs text-slate-500 text-center pt-2">
                Showing {data.events.length} of {data.total} events
              </div>
            </div>
          ) : (
            <EmptyState
              icon=""
              title="No Events Yet"
              desc="Run analyses in the Security Playground to generate security events."
            />
          )}
        </div>

        {/* Event Detail */}
        <div className="card">
          {selected ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="font-semibold text-white">Event Detail</h2>
                <DecisionBadge decision={selected.policy_decision as 'ALLOW' | 'QUARANTINE' | 'BLOCK'} />
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                {[
                  ['Event ID', selected.event_id.slice(0, 12) + '…'],
                  ['Request ID', selected.request_id.slice(0, 12) + '…'],
                  ['Source', selected.source_type],
                  ['Risk Score', `${selected.risk_score.toFixed(1)} / 100`],
                  ['Risk Category', selected.risk_category],
                  ['Latency', `${selected.latency_ms.toFixed(1)} ms`],
                  ['Mode', selected.execution_mode],
                  ['Session', selected.session_id || '—'],
                  ['Timestamp', new Date(selected.timestamp).toLocaleString()],
                ].map(([k, v]) => (
                  <div key={k} className="p-2 bg-navy-900 rounded-lg">
                    <div className="text-xs text-slate-500 mb-0.5">{k}</div>
                    <div className="font-mono text-xs text-slate-200 break-all">{v}</div>
                  </div>
                ))}
              </div>

              {selected.attack_types.length > 0 && (
                <div>
                  <div className="section-title">Attack Types</div>
                  <div className="flex flex-wrap gap-2">
                    {selected.attack_types.map(t => (
                      <span key={t} className="px-2 py-0.5 bg-cyber-red/10 border border-cyber-red/20 rounded text-cyber-red text-xs">
                        {t.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div className="section-title">Summary</div>
                <p className="text-slate-300 text-sm">{selected.summary}</p>
              </div>

              <div className="text-xs text-slate-500 italic">
                ℹ Trace is stored locally. LangSmith integration available when configured.
              </div>
            </div>
          ) : (
            <EmptyState
              icon=""
              title="Select an Event"
              desc="Click an event on the left to inspect its details."
            />
          )}
        </div>
      </div>
    </div>
  );
};
