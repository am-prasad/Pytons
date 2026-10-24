import React, { useState } from 'react';
import type { EvaluationResult } from '../types/api';
import { runEvaluation, getEvaluationResults } from '../services/api';
import { Spinner, EmptyState } from '../components/ui/Badges';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts';

const MetricCard: React.FC<{ label: string; value: string; color?: string; desc?: string }> = ({
  label, value, color = 'text-cyber-blue', desc
}) => (
  <div className="card text-center">
    <div className="text-3xl font-bold font-mono mb-1" style={{ color: color === 'text-cyber-blue' ? '#00d4ff' : color === 'text-cyber-green' ? '#10b981' : color === 'text-cyber-red' ? '#ef4444' : '#f59e0b' }}>
      {value}
    </div>
    <div className="text-xs text-slate-400 font-semibold uppercase tracking-wide">{label}</div>
    {desc && <div className="text-xs text-slate-500 mt-1">{desc}</div>}
  </div>
);

export const EvaluationPage: React.FC = () => {
  const [result, setResult] = useState<EvaluationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [maxExamples, setMaxExamples] = useState<number>(25);

  const handleRun = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await runEvaluation(maxExamples);
      setResult(res);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Evaluation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadLatest = async () => {
    try {
      const res = await getEvaluationResults();
      setResult(res);
    } catch {
      setError('No previous evaluation results found.');
    }
  };

  const categoryData = result?.category_metrics.map(m => ({
    name: m.label.replace(/_/g, ' '),
    total: m.total,
    correct: m.correct,
    accuracy: m.total > 0 ? Math.round((m.correct / m.total) * 100) : 0,
  })) ?? [];

  const confusionKeys = result ? Object.keys(result.confusion_matrix) : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white mb-1">Evaluation Lab</h1>
        <p className="text-slate-400 text-sm">
          Run the labeled security dataset through the pipeline and compute real detection metrics.
        </p>
      </div>

      {/* Controls */}
      <div className="card flex flex-wrap items-center gap-4">
        <div>
          <label className="section-title block">Max Examples</label>
          <input
            type="number"
            value={maxExamples}
            onChange={e => setMaxExamples(Number(e.target.value))}
            min={5} max={25}
            className="input-field w-24"
          />
        </div>
        <div className="flex gap-3 mt-4">
          <button
            id="run-eval-btn"
            onClick={handleRun}
            disabled={loading}
            className="btn-primary flex items-center gap-2"
          >
            {loading ? <><Spinner className="w-4 h-4" /> Running...</> : '▶ Run Evaluation'}
          </button>
          <button onClick={handleLoadLatest} className="btn-ghost">
            Load Latest
          </button>
        </div>
        {loading && (
          <div className="text-slate-400 text-sm">
            Processing {maxExamples} examples... (~30-90s without Groq)
          </div>
        )}
      </div>

      {error && (
        <div className="bg-cyber-red/10 border border-cyber-red/30 rounded-lg px-4 py-3 text-cyber-red text-sm">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-6 animate-fade-in">
          {/* Key Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <MetricCard
              label="Attack Recall"
              value={`${(result.attack_recall * 100).toFixed(0)}%`}
              color="text-cyber-green"
              desc="True attack detections"
            />
            <MetricCard
              label="Precision"
              value={`${(result.precision * 100).toFixed(0)}%`}
              color="text-cyber-blue"
              desc="Of detected: truly malicious"
            />
            <MetricCard
              label="False Positive Rate"
              value={`${(result.false_positive_rate * 100).toFixed(0)}%`}
              color="text-cyber-red"
              desc="Benign flagged as attack"
            />
            <MetricCard
              label="Dangerous Block Rate"
              value={`${(result.block_rate_on_dangerous * 100).toFixed(0)}%`}
              color="text-cyber-amber"
              desc="Attack inputs blocked"
            />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <MetricCard label="Total Examples" value={String(result.total_examples)} />
            <MetricCard label="Median Latency" value={result.median_latency_ms ? `${result.median_latency_ms.toFixed(0)}ms` : '—'} />
            <MetricCard label="Execution Mode" value={result.execution_mode} />
          </div>

          {/* Category Accuracy Chart */}
          <div className="card">
            <h2 className="font-semibold text-white mb-4">Per-Category Accuracy</h2>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={categoryData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a2640" />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis domain={[0, 100]} tick={{ fill: '#94a3b8', fontSize: 11 }} unit="%" />
                <Tooltip
                  contentStyle={{ background: '#0d1b2e', border: '1px solid #1a3356', borderRadius: 8 }}
                  labelStyle={{ color: '#e2e8f0' }}
                  formatter={(v: number) => [`${v}%`, 'Accuracy']}
                />
                <Bar dataKey="accuracy" radius={[4, 4, 0, 0]}>
                  {categoryData.map((entry, i) => (
                    <Cell
                      key={i}
                      fill={
                        entry.accuracy >= 80 ? '#10b981' :
                        entry.accuracy >= 50 ? '#f59e0b' :
                        '#ef4444'
                      }
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Confusion Matrix */}
          {confusionKeys.length > 0 && (
            <div className="card">
              <h2 className="font-semibold text-white mb-4">Confusion Matrix</h2>
              <div className="overflow-x-auto">
                <table className="text-sm w-full">
                  <thead>
                    <tr>
                      <th className="text-left text-slate-500 pb-2 pr-4">Expected →<br />Actual ↓</th>
                      {confusionKeys.map(k => (
                        <th key={k} className="text-center text-slate-300 pb-2 px-3 font-mono">{k}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {confusionKeys.map(actual => (
                      <tr key={actual}>
                        <td className="text-slate-400 font-mono pr-4 py-1.5">{actual}</td>
                        {confusionKeys.map(expected => {
                          const val = result.confusion_matrix[expected]?.[actual] ?? 0;
                          const isCorrect = actual === expected;
                          return (
                            <td key={expected} className="text-center py-1.5 px-3">
                              <span className={`font-mono font-bold ${
                                val === 0 ? 'text-slate-600' :
                                isCorrect ? 'text-cyber-green' :
                                'text-cyber-red'
                              }`}>
                                {val}
                              </span>
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Notes */}
          <div className="card border-l-2 border-cyber-amber/40">
            <div className="section-title">Evaluation Notes</div>
            <p className="text-slate-400 text-sm">{result.notes}</p>
            <p className="text-slate-500 text-xs mt-2">
              Run timestamp: {new Date(result.timestamp).toLocaleString()} | Run ID: {result.run_id.slice(0, 12)}…
            </p>
          </div>
        </div>
      )}

      {!result && !loading && (
        <EmptyState
          icon=""
          title="No Evaluation Results"
          desc="Click 'Run Evaluation' to execute the labeled dataset through the security pipeline."
        />
      )}
    </div>
  );
};
