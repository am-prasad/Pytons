import React from 'react';
import type { AnalyzeResponse } from '../types/api';
import { RiskScoreRing, DecisionBadge, RiskBadge, StatusDot } from './ui/Badges';

interface ResultsPanelProps {
  result: AnalyzeResponse;
}

export const ResultsPanel: React.FC<ResultsPanelProps> = ({ result }) => {
  return (
    <div className="space-y-4">
      {/* Top Summary Card */}
      <div className="card grid grid-cols-2 sm:grid-cols-4 gap-6 items-center">
        <div className="flex justify-center">
          <RiskScoreRing score={result.risk_score} size={88} />
        </div>
        <div className="space-y-1.5">
          <div className="section-title mb-1">Policy Decision</div>
          <div>
            <DecisionBadge decision={result.policy_decision} large />
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            Enforced by Policy Gate
          </div>
        </div>
        <div className="space-y-1.5">
          <div className="section-title mb-1">Risk Band</div>
          <div>
            <RiskBadge category={result.risk_category} />
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
            {result.risk_score.toFixed(1)} / 100
          </div>
        </div>
        <div className="space-y-1.5">
          <div className="section-title mb-1">Latency & Mode</div>
          <div className="font-mono text-lg font-bold text-slate-900 dark:text-slate-100">
            {result.latency_ms.toFixed(0)} ms
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
            Mode: {result.execution_mode}
          </div>
        </div>
      </div>

      {/* Detected Threats */}
      {result.attack_types.length > 0 && (
        <div className="card">
          <div className="section-title">Detected Attack Signatures</div>
          <div className="flex flex-wrap gap-2">
            {result.attack_types.map(t => (
              <span
                key={t}
                className="px-2.5 py-1 rounded bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-900 text-xs font-mono font-medium uppercase"
              >
                {t.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Policy Explanation */}
      <div className="card">
        <div className="section-title">Enforcement Rationale</div>
        <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
          {result.policy_result.explanation}
        </p>
        {result.policy_result.blocked_reason && (
          <div className="mt-3 p-2.5 bg-rose-50 dark:bg-rose-950/50 border-l-3 border-rose-600 rounded-r text-xs text-rose-800 dark:text-rose-300 font-mono">
            Block Rule: {result.policy_result.blocked_reason}
          </div>
        )}
      </div>

      {/* Two Columns: Fast Scanner (Layer 1) & Contextual Analyzer (Layer 2) */}
      <div className="grid md:grid-cols-2 gap-4">
        {/* Layer 1: Scanner */}
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="section-title mb-0">Layer 1 · Fast Screening</span>
            <span className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300">
              Raw Score: {result.scanner_findings.raw_score.toFixed(0)}/100
            </span>
          </div>

          {result.scanner_findings.patterns_matched.length > 0 ? (
            <div className="space-y-1.5 mt-3">
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Matched {result.scanner_findings.patterns_matched.length} heuristic patterns:
              </div>
              <ul className="space-y-1 text-xs">
                {result.scanner_findings.patterns_matched.map((p, idx) => (
                  <li key={idx} className="flex items-center gap-2 font-mono text-slate-800 dark:text-slate-200">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500 flex-shrink-0" />
                    <span>{p}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-2">
              No known hostile patterns matched in fast heuristic catalog.
            </div>
          )}
        </div>

        {/* Layer 2: Contextual Analysis */}
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="section-title mb-0">Layer 2 · Contextual Judge</span>
            <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              {result.contextual_findings.provider}
            </span>
          </div>

          <div className="space-y-2 mt-3 text-xs">
            <div className="flex items-center justify-between py-1 border-b border-slate-100 dark:border-slate-800">
              <span className="text-slate-500 dark:text-slate-400">Classification</span>
              <span className="font-semibold text-slate-800 dark:text-slate-200 uppercase">
                {result.contextual_findings.attack_category.replace(/_/g, ' ')}
              </span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-slate-100 dark:border-slate-800">
              <span className="text-slate-500 dark:text-slate-400">Confidence</span>
              <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                {(result.contextual_findings.confidence * 100).toFixed(0)}%
              </span>
            </div>
            <div className="flex items-center justify-between py-1">
              <span className="text-slate-500 dark:text-slate-400">Recommended Action</span>
              <DecisionBadge decision={result.contextual_findings.recommended_action} />
            </div>

            {result.contextual_findings.note && (
              <div className="mt-2 text-[11px] text-slate-500 dark:text-slate-400 italic">
                {result.contextual_findings.note}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Evidence Trail */}
      {result.evidence.length > 0 && (
        <div className="card">
          <div className="section-title">Evidence & Extraction Artifacts</div>
          <div className="space-y-2 mt-2">
            {result.evidence.slice(0, 6).map((item, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-start gap-3"
              >
                <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 flex-shrink-0 mt-0.5">
                  {item.layer}
                </span>
                <div className="space-y-0.5 min-w-0 flex-1">
                  <div className="font-mono text-xs text-amber-700 dark:text-amber-400 truncate">
                    "{item.text}"
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    {item.indicator}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Execution Nodes / Pipeline Trace */}
      {result.workflow_nodes && result.workflow_nodes.length > 0 && (
        <div className="card">
          <div className="section-title">LangGraph Checkpoint Pipeline</div>
          <div className="divide-y divide-slate-100 dark:divide-slate-800 mt-2">
            {result.workflow_nodes.map((node, i) => (
              <div key={i} className="py-2 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <StatusDot status={node.status} />
                  <span className="font-mono font-medium text-slate-800 dark:text-slate-200">
                    {node.name}
                  </span>
                  {node.detail && (
                    <span className="text-slate-400 dark:text-slate-500 text-[11px]">
                      — {node.detail}
                    </span>
                  )}
                </div>
                <span className="font-mono text-slate-500 dark:text-slate-400 text-[11px]">
                  {node.duration_ms.toFixed(1)} ms
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
