import React, { useState } from 'react';
import type { AnalyzeResponse, AttackScenario } from '../types/api';
import { analyzeInput } from '../services/api';
import { ATTACK_SCENARIOS } from '../services/scenarios';
import { DecisionBadge, RiskScoreRing, Spinner, ErrorBanner } from '../components/ui/Badges';

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
      setError(e instanceof Error ? e.message : 'Evaluation failed. Check backend connection.');
    } finally {
      setLoading(false);
      setActive('');
    }
  };

  const runAll = async () => {
    setLoading(true);
    setError(null);
    for (const s of ATTACK_SCENARIOS) {
      setActive(s.id);
      try {
        const res = await analyzeInput({
          text: s.text,
          source_type: s.source_type,
          scenario_id: s.id,
          session_id: 'scenarios-demo-batch',
        });
        setResults(prev => ({ ...prev, [s.id]: res }));
      } catch {}
      await new Promise(r => setTimeout(r, 200));
    }
    setActive('');
    setLoading(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Attack Scenario Benchmark Suite
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Standard test cases covering direct injection, RAG poisoning, tool tampering, and benign false-positive controls.
          </p>
        </div>
        <button
          onClick={runAll}
          disabled={loading}
          className="btn-primary self-start sm:self-auto flex items-center gap-2"
        >
          {loading && <Spinner className="w-3.5 h-3.5" />}
          <span>{loading ? 'Evaluating All...' : 'Run All Scenarios'}</span>
        </button>
      </div>

      {error && <ErrorBanner message={error} />}

      {/* Grid of Scenarios */}
      <div className="grid md:grid-cols-2 gap-4">
        {ATTACK_SCENARIOS.map(scenario => {
          const result = results[scenario.id];
          const isRunning = active === scenario.id && loading;

          return (
            <div
              key={scenario.id}
              className={`card flex flex-col justify-between transition-colors ${
                result
                  ? result.policy_decision === 'BLOCK'
                    ? 'border-rose-300 dark:border-rose-900'
                    : result.policy_decision === 'QUARANTINE'
                    ? 'border-amber-300 dark:border-amber-900'
                    : 'border-emerald-300 dark:border-emerald-900'
                  : ''
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div>
                    <h3 className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                      {scenario.name}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      {scenario.description}
                    </p>
                  </div>
                  {result && (
                    <div className="flex-shrink-0">
                      <RiskScoreRing score={result.risk_score} size={64} />
                    </div>
                  )}
                </div>

                {/* Expected vs Actual */}
                <div className="flex items-center gap-2 my-3 text-xs flex-wrap">
                  <span className="text-slate-500 dark:text-slate-400">Expected:</span>
                  <DecisionBadge decision={scenario.expectedDecision} />
                  {result && (
                    <>
                      <span className="text-slate-400 dark:text-slate-600 ml-1">/</span>
                      <span className="text-slate-500 dark:text-slate-400">Actual:</span>
                      <DecisionBadge decision={result.policy_decision} />
                      <span className={`font-mono text-[11px] font-semibold ${
                        result.policy_decision === scenario.expectedDecision
                          ? 'text-emerald-700 dark:text-emerald-400'
                          : 'text-amber-700 dark:text-amber-400'
                      }`}>
                        {result.policy_decision === scenario.expectedDecision ? 'Match' : 'Mismatch'}
                      </span>
                    </>
                  )}
                </div>

                {/* Snippet Preview */}
                <div className="p-2.5 rounded bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs font-mono text-slate-700 dark:text-slate-300 line-clamp-3 mb-3 leading-relaxed">
                  {scenario.text}
                </div>

                {result && (
                  <div className="text-xs space-y-1 mb-3 pt-2 border-t border-slate-100 dark:border-slate-800 text-slate-600 dark:text-slate-400">
                    <div className="flex justify-between">
                      <span>Scanner Score:</span>
                      <span className="font-mono font-medium text-slate-800 dark:text-slate-200">
                        {result.scanner_findings.raw_score.toFixed(0)}/100
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span>Detected Class:</span>
                      <span className="font-mono font-medium text-slate-800 dark:text-slate-200 uppercase">
                        {result.contextual_findings.attack_category.replace(/_/g, ' ')}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              <button
                id={`run-scenario-${scenario.id}`}
                onClick={() => runScenario(scenario)}
                disabled={isRunning || loading}
                className="btn-ghost w-full text-center text-xs py-1.5 flex items-center justify-center gap-1.5 mt-2"
              >
                {isRunning ? (
                  <>
                    <Spinner className="w-3 h-3" />
                    <span>Evaluating...</span>
                  </>
                ) : (
                  <span>Test Scenario</span>
                )}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
};
