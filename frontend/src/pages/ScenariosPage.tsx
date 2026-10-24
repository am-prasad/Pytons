import React, { useState } from 'react';
import type { AnalyzeResponse, AttackScenario } from '../types/api';
import { analyzeInput } from '../services/api';
import { ATTACK_SCENARIOS } from '../services/scenarios';
import { DecisionBadge, RiskScoreRing, Spinner } from '../components/ui/Badges';

export const ScenariosPage: React.FC = () => {
  const [active, setActive] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<Record<string, AnalyzeResponse>>({});
  const [error, setError] = useState<string | null>(null);

  const runScenario = async (scenario: AttackScenario) => {
    setActive(scenario.id);
    setLoading(true);
    setError(null);
    try {
      const res = await analyzeInput({
        text: scenario.text,
        source_type: scenario.source_type,
        scenario_id: scenario.id,
        session_id: 'scenarios-demo',
      });
      setResults(prev => ({ ...prev, [scenario.id]: res }));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed. Backend offline?');
    } finally {
      setLoading(false);
      setActive('');
    }
  };

  const runAll = async () => {
    for (const s of ATTACK_SCENARIOS) {
      setActive(s.id);
      try {
        const res = await analyzeInput({
          text: s.text,
          source_type: s.source_type,
          scenario_id: s.id,
          session_id: 'scenarios-demo-all',
        });
        setResults(prev => ({ ...prev, [s.id]: res }));
      } catch {}
      await new Promise(r => setTimeout(r, 300));
    }
    setActive('');
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Attack Scenarios</h1>
          <p className="text-slate-400 text-sm">
            Pre-built attack scenarios to demonstrate detection across different attack types.
          </p>
        </div>
        <button
          onClick={() => { setLoading(true); runAll(); }}
          disabled={loading}
          className="btn-primary flex items-center gap-2"
        >
          {loading ? <Spinner className="w-4 h-4" /> : null}
          Run All
        </button>
      </div>

      {error && (
        <div className="bg-cyber-red/10 border border-cyber-red/30 rounded-lg px-4 py-3 text-cyber-red text-sm">{error}</div>
      )}

      <div className="grid md:grid-cols-2 gap-4">
        {ATTACK_SCENARIOS.map(scenario => {
          const result = results[scenario.id];
          const isRunning = active === scenario.id && loading;

          return (
            <div key={scenario.id} className={`card border transition-all ${
              result
                ? result.policy_decision === 'BLOCK' ? 'border-cyber-red/30' :
                  result.policy_decision === 'QUARANTINE' ? 'border-cyber-amber/30' :
                  'border-cyber-green/30'
                : 'border-navy-700'
            }`}>
              <div className="flex items-start justify-between gap-3 mb-3">
                <div>
                  <h3 className="font-semibold text-white text-sm">{scenario.name}</h3>
                  <p className="text-slate-400 text-xs mt-0.5">{scenario.description}</p>
                </div>
                {result && <RiskScoreRing score={result.risk_score} size={60} />}
              </div>

              {/* Expected vs Actual */}
              <div className="flex items-center gap-3 mb-3">
                <div className="text-xs text-slate-500">Expected:</div>
                <DecisionBadge decision={scenario.expectedDecision} />
                {result && (
                  <>
                    <div className="text-xs text-slate-500">Actual:</div>
                    <DecisionBadge decision={result.policy_decision} />
                    {result.policy_decision === scenario.expectedDecision ? (
                      <span className="text-xs text-cyber-green">✓ Correct</span>
                    ) : (
                      <span className="text-xs text-cyber-amber">≠ Mismatch</span>
                    )}
                  </>
                )}
              </div>

              {/* Input Preview */}
              <div className="bg-navy-950 rounded-lg p-3 mb-3 text-xs font-mono text-slate-400 line-clamp-3 border border-navy-700">
                {scenario.text.slice(0, 200)}{scenario.text.length > 200 ? '…' : ''}
              </div>

              {/* Result summary */}
              {result && (
                <div className="text-xs text-slate-400 mb-3 space-y-1">
                  <div>Attack type: <span className="text-slate-200">{result.contextual_findings.attack_category}</span></div>
                  <div>Scanner score: <span className="font-mono text-cyber-blue">{result.scanner_findings.raw_score.toFixed(0)}/100</span></div>
                  <div className="text-slate-500 italic truncate">{result.policy_result.explanation.slice(0, 100)}</div>
                </div>
              )}

              <button
                id={`run-scenario-${scenario.id}`}
                onClick={() => runScenario(scenario)}
                disabled={isRunning || loading}
                className="btn-ghost w-full text-center text-xs py-1.5 flex items-center justify-center gap-2"
              >
                {isRunning ? <><Spinner className="w-3 h-3" /> Running...</> : '▶ Run This Scenario'}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
};
