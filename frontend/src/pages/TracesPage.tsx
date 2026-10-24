import React, { useEffect, useState } from 'react';
import type { SecurityEvent, EventListResponse } from '../types/api';
import { getEvents } from '../services/api';
import { DecisionBadge, EmptyState, Spinner } from '../components/ui/Badges';

export const TracesPage: React.FC = () => {
  const [data, setData] = useState<EventListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [error, setError] = useState(false);

  const load = async (page = 1) => {
    setLoading(true);
    try {
      const res = await getEvents(page, 25);
      setData(res);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Execution Audit Traces
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Immutable event log tracking input provenance, policy outcomes, and node timing.
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6 items-start">
        {/* Left Column: Event List */}
        <div className="card space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Audit Stream
            </h2>
            <button onClick={() => load()} className="btn-ghost text-xs py-1 px-2.5">
              Refresh
            </button>
          </div>

          {loading ? (
            <div className="flex justify-center py-12"><Spinner className="w-5 h-5" /></div>
          ) : error ? (
            <div className="text-xs text-rose-700 dark:text-rose-400 p-3 bg-rose-50 dark:bg-rose-950/40 rounded border border-rose-200 dark:border-rose-900">
              Failed to load audit events. Ensure backend is running.
            </div>
          ) : data && data.events.length > 0 ? (
            <div className="space-y-2">
              {data.events.map(e => {
                const isSelected = selected?.event_id === e.event_id;
                return (
                  <button
                    key={e.event_id}
                    onClick={() => setSelected(e)}
                    className={`w-full text-left p-2.5 rounded-md border text-xs transition-colors ${
                      isSelected
                        ? 'border-slate-900 bg-slate-100 dark:border-slate-100 dark:bg-slate-800'
                        : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 hover:bg-slate-50 dark:hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2">
                        <DecisionBadge decision={e.policy_decision as 'ALLOW' | 'QUARANTINE' | 'BLOCK'} />
                        <span className="font-mono text-[11px] text-slate-600 dark:text-slate-400">
                          {e.source_type.replace(/_/g, ' ')}
                        </span>
                      </div>
                      <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                        {e.risk_score.toFixed(0)}/100
                      </span>
                    </div>

                    <div className="font-mono text-[11px] text-slate-700 dark:text-slate-300 truncate">
                      {e.summary}
                    </div>

                    <div className="flex items-center justify-between mt-1 text-[10px] text-slate-400 dark:text-slate-500 font-mono">
                      <span>{e.execution_mode}</span>
                      <span>{new Date(e.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </button>
                );
              })}

              <div className="text-[11px] text-slate-500 dark:text-slate-400 text-center pt-2 font-mono">
                Showing {data.events.length} of {data.total} recorded events
              </div>
            </div>
          ) : (
            <EmptyState
              title="No Audit Records"
              desc="Run analyses in the Playground or Scenarios suite to record security checkpoints."
            />
          )}
        </div>

        {/* Right Column: Event Detail */}
        <div className="card">
          {selected ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  Event Inspection
                </h2>
                <DecisionBadge decision={selected.policy_decision as 'ALLOW' | 'QUARANTINE' | 'BLOCK'} />
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                {[
                  ['Event ID', selected.event_id],
                  ['Request ID', selected.request_id],
                  ['Source Provenance', selected.source_type],
                  ['Risk Score', `${selected.risk_score.toFixed(1)} / 100`],
                  ['Risk Category', selected.risk_category],
                  ['Pipeline Latency', `${selected.latency_ms.toFixed(1)} ms`],
                  ['Execution Mode', selected.execution_mode],
                  ['Session Key', selected.session_id || 'unassigned'],
                  ['Timestamp', new Date(selected.timestamp).toLocaleString()],
                ].map(([k, v]) => (
                  <div key={k} className="p-2 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] uppercase font-semibold text-slate-500 dark:text-slate-400 mb-0.5 tracking-wider">
                      {k}
                    </div>
                    <div className="font-mono text-xs text-slate-800 dark:text-slate-200 truncate">
                      {v}
                    </div>
                  </div>
                ))}
              </div>

              {selected.attack_types.length > 0 && (
                <div>
                  <div className="section-title">Detected Threat Signatures</div>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {selected.attack_types.map(t => (
                      <span
                        key={t}
                        className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-900 text-xs font-mono uppercase"
                      >
                        {t.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div className="section-title">Log Summary</div>
                <div className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-xs text-slate-800 dark:text-slate-200 leading-relaxed">
                  {selected.summary}
                </div>
              </div>

              <div className="text-[11px] text-slate-500 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800 pt-3">
                Events are recorded in local SQLite database. LangSmith distributed spans are automatically linked when credentials are active.
              </div>
            </div>
          ) : (
            <EmptyState
              title="Select an Audit Record"
              desc="Select an event from the audit stream on the left to inspect its parameters, timing, and security scores."
            />
          )}
        </div>
      </div>
    </div>
  );
};
