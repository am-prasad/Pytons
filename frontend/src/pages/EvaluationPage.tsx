import React, { useState } from 'react';
import type { EvaluationResult } from '../types/api';
import { runEvaluation, getEvaluationResults } from '../services/api';
import { Spinner, EmptyState, ErrorBanner } from '../components/ui/Badges';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts';

const MetricCard: React.FC<{
  label: string;
  value: string;
  sub?: string;
  tone?: 'good' | 'warn' | 'danger' | 'neutral';
}> = ({ label, value, sub, tone = 'neutral' }) => {
  const toneClass = {
    good: 'text-emerald-700 dark:text-emerald-400',
    warn: 'text-amber-700 dark:text-amber-400',
    danger: 'text-rose-700 dark:text-rose-400',
    neutral: 'text-slate-900 dark:text-slate-100',
  }[tone];

  return (
    <div className="card text-center">
      <div className={`text-2xl font-bold font-mono tracking-tight mb-1 ${toneClass}`}>
        {value}
      </div>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
        {label}
      </div>
      {sub && <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">{sub}</div>}
    </div>
  );
};

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
      setError(e instanceof Error ? e.message : 'Evaluation benchmark failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadLatest = async () => {
    try {
      const res = await getEvaluationResults();
      setResult(res);
    } catch {
      setError('No prior evaluation runs found.');
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
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Empirical Evaluation Lab
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Measure attack recall, precision, and benign false positive rate against ground-truth security samples.
        </p>
      </div>

      {/* Control Bar */}
      <div className="card flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div>
            <label htmlFor="eval-limit" className="section-title block mb-1">
              Sample Count
            </label>
            <input
              id="eval-limit"
              type="number"
              value={maxExamples}
              onChange={e => setMaxExamples(Number(e.target.value))}
              min={5}
              max={25}
              className="input-field w-24 text-xs font-mono"
            />
          </div>

          <div className="self-end flex gap-2">
            <button
              id="run-eval-btn"
              onClick={handleRun}
              disabled={loading}
              className="btn-primary flex items-center gap-2"
            >
              {loading && <Spinner className="w-3.5 h-3.5" />}
              <span>{loading ? 'Executing Benchmark...' : 'Run Benchmark'}</span>
            </button>

            <button
              onClick={handleLoadLatest}
              disabled={loading}
              className="btn-ghost"
            >
              Load Previous
            </button>
          </div>
        </div>

        {loading && (
          <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
            Evaluating {maxExamples} samples sequentially...
          </div>
        )}
      </div>

      {error && <ErrorBanner message={error} />}

      {result && (
        <div className="space-y-6">
          {/* Primary Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <MetricCard
              label="Attack Recall"
              value={`${(result.attack_recall * 100).toFixed(1)}%`}
              tone={result.attack_recall >= 0.8 ? 'good' : 'warn'}
              sub="Malicious inputs detected"
            />
            <MetricCard
              label="Precision"
              value={`${(result.precision * 100).toFixed(1)}%`}
              tone={result.precision >= 0.8 ? 'good' : 'warn'}
              sub="True positive accuracy"
            />
            <MetricCard
              label="False Positive Rate"
              value={`${(result.false_positive_rate * 100).toFixed(1)}%`}
              tone={result.false_positive_rate === 0 ? 'good' : 'danger'}
              sub="Benign queries flagged"
            />
            <MetricCard
              label="Unauthorized Block Rate"
              value={`${(result.block_rate_on_dangerous * 100).toFixed(1)}%`}
              tone={result.block_rate_on_dangerous >= 0.8 ? 'good' : 'warn'}
              sub="Dangerous actions prevented"
            />
          </div>

          {/* Operational Secondary Stats */}
          <div className="grid grid-cols-3 gap-4">
            <MetricCard label="Sample Size" value={String(result.total_examples)} sub="Ground-truth cases" />
            <MetricCard
              label="Median Latency"
              value={result.median_latency_ms ? `${result.median_latency_ms.toFixed(0)} ms` : '—'}
              sub="Per-request execution"
            />
            <MetricCard label="Pipeline Mode" value={result.execution_mode} sub="Active judge runtime" />
          </div>

          {/* Per-Category Accuracy Chart */}
          <div className="card">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-4">
              Category Accuracy Distribution
            </h2>
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="2 2" stroke="currentColor" className="text-slate-200 dark:text-slate-800" />
                  <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="currentColor" className="text-slate-500" />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} unit="%" stroke="currentColor" className="text-slate-500" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(15, 23, 42, 0.95)',
                      borderColor: 'rgba(51, 65, 85, 0.5)',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                    formatter={(v: number) => [`${v}%`, 'Accuracy']}
                  />
                  <Bar dataKey="accuracy" radius={[3, 3, 0, 0]}>
                    {categoryData.map((entry, i) => (
                      <Cell
                        key={i}
                        fill={
                          entry.accuracy >= 80 ? '#059669' :
                          entry.accuracy >= 50 ? '#d97706' :
                          '#e11d48'
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Confusion Matrix */}
          {confusionKeys.length > 0 && (
            <div className="card">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">
                Confusion Matrix
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800">
                      <th className="text-left text-slate-500 pb-2 pr-4 font-normal">
                        Expected Label →<br />Actual Policy ↓
                      </th>
                      {confusionKeys.map(k => (
                        <th key={k} className="text-center text-slate-700 dark:text-slate-300 pb-2 px-3 font-mono font-semibold">
                          {k}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
                    {confusionKeys.map(actual => (
                      <tr key={actual}>
                        <td className="text-slate-600 dark:text-slate-400 pr-4 py-2 font-semibold">
                          {actual}
                        </td>
                        {confusionKeys.map(expected => {
                          const val = result.confusion_matrix[expected]?.[actual] ?? 0;
                          const isCorrect = actual === expected;
                          return (
                            <td key={expected} className="text-center py-2 px-3">
                              <span className={`inline-block px-2 py-0.5 rounded ${
                                val === 0
                                  ? 'text-slate-400 dark:text-slate-600'
                                  : isCorrect
                                  ? 'font-bold text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40'
                                  : 'font-bold text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/40'
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

          {/* Methodology Notes */}
          <div className="card border-l-3 border-slate-400 dark:border-slate-600">
            <div className="section-title">Benchmark Documentation</div>
            <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
              {result.notes}
            </p>
            <div className="font-mono text-[10px] text-slate-400 dark:text-slate-500 mt-2">
              Run ID: {result.run_id} · Timestamp: {new Date(result.timestamp).toUTCString()}
            </div>
          </div>
        </div>
      )}

      {!result && !loading && (
        <EmptyState
          title="Benchmark Not Yet Run"
          desc="Click 'Run Benchmark' to execute the 25 labeled test cases and observe computed precision, recall, and false positive metrics."
        />
      )}
    </div>
  );
};
