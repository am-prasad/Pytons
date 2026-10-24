import React from 'react';
import type { AnalyzeResponse } from '../../types/api';
import { RiskScoreRing, DecisionBadge, RiskBadge, StatusDot } from '@/components/ui/Badges';

interface ResultsPanelProps {
  result: AnalyzeResponse;
}

export const ResultsPanel: React.FC<ResultsPanelProps> = ({ result }) => {
  return (
    <div className="space-y-4 animate-fade-in">
      {/* Top Summary Row */}
      <div className="card-cyber grid grid-cols-2 md:grid-cols-4 gap-6 items-center">
        <div className="flex justify-center">
          <RiskScoreRing score={result.risk_score} size={100} />
        </div>
        <div className="space-y-2">
          <div className="section-title">Policy Decision</div>
          <DecisionBadge decision={result.policy_decision} large />
        </div>
        <div className="space-y-2">
          <div className="section-title">Risk Category</div>
          <RiskBadge category={result.risk_category} />
        </div>
        <div className="space-y-2">
          <div className="section-title">Latency</div>
          <div className="text-cyber-blue font-mono text-lg">{result.latency_ms.toFixed(0)} ms</div>
          <div className="text-xs text-slate-500">Mode: {result.execution_mode}</div>
        </div>
      </div>

      {/* Attack Types */}
      {result.attack_types.length > 0 && (
        <div className="card">
          <div className="section-title">Detected Attack Types</div>
          <div className="flex flex-wrap gap-2">
            {result.attack_types.map(t => (
              <span key={t} className="px-3 py-1 bg-cyber-red/10 border border-cyber-red/30 rounded-full text-cyber-red text-xs font-semibold uppercase">
                {t.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Policy Explanation */}
      <div className="card">
        <div className="section-title">Policy Explanation</div>
        <p className="text-slate-300 text-sm leading-relaxed">{result.policy_result.explanation}</p>
        {result.policy_result.blocked_reason && (
          <div className="mt-3 px-3 py-2 bg-cyber-red/5 border-l-2 border-cyber-red rounded text-cyber-red text-xs">
            Blocked: {result.policy_result.blocked_reason}
          </div>
        )}
      </div>

      {/* Scanner + Contextual side by side */}
      <div className="grid md:grid-cols-2 gap-4">
        {/* Scanner Findings */}
        <div className="card">
          <div className="section-title">Layer 1: Fast Scanner</div>
          <div className="flex items-center gap-3 mb-3">
            <div className="text-2xl font-bold text-cyber-blue font-mono">
              {result.scanner_findings.raw_score.toFixed(0)}
            </div>
            <span className="text-slate-400 text-sm">/ 100</span>
          </div>
          {result.scanner_findings.patterns_matched.length > 0 ? (
            <div className="space-y-1">
              {result.scanner_findings.patterns_matched.slice(0, 6).map((p, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className="text-cyber-red mt-0.5">▸</span>
                  <span className="font-mono text-slate-300">{p}</span>
                </div>
              ))}
              {result.scanner_findings.patterns_matched.length > 6 && (
                <div className="text-xs text-slate-500">
                  +{result.scanner_findings.patterns_matched.length - 6} more patterns
                </div>
              )}
            </div>
          ) : (
            <div className="text-slate-500 text-xs">No patterns matched</div>
          )}
        </div>

        {/* Contextual Analysis */}
        <div className="card">
          <div className="section-title">Layer 2: Contextual Analysis</div>
          <div className="space-y-2 mb-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Attack Category</span>
              <span className="text-cyber-blue font-semibold capitalize">
                {result.contextual_findings.attack_category.replace(/_/g, ' ')}
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Confidence</span>
              <span className="text-slate-200 font-mono">
                {(result.contextual_findings.confidence * 100).toFixed(0)}%
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Provider</span>
              <span className="text-slate-400 text-xs bg-navy-700 px-2 py-0.5 rounded">
                {result.contextual_findings.provider}
              </span>
            </div>
          </div>
          {result.contextual_findings.note && (
            <div className="text-xs text-slate-500 italic">{result.contextual_findings.note}</div>
          )}
        </div>
      </div>

      {/* Evidence */}
      {result.evidence.length > 0 && (
        <div className="card">
          <div className="section-title">Evidence ({result.evidence.length} indicators)</div>
          <div className="space-y-2">
            {result.evidence.slice(0, 8).map((e, i) => (
              <div key={i} className="flex items-start gap-3 p-2 bg-navy-900 rounded-lg">
                <span className={`text-xs px-1.5 py-0.5 rounded flex-shrink-0 mt-0.5 ${
                  e.layer === 'scanner' ? 'bg-cyber-blue/10 text-cyber-blue' :
                  e.layer === 'contextual' ? 'bg-cyber-purple/10 text-purple-400' :
                  'bg-slate-700 text-slate-400'
                }`}>
                  {e.layer}
                </span>
                <div>
                  <div className="text-xs font-mono text-amber-400 mb-0.5 line-clamp-1">{e.text}</div>
                  <div className="text-xs text-slate-500">{e.indicator}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Session Correlation */}
      {result.session_id && (
        <div className="card">
          <div className="section-title">Session Correlation</div>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <div className="text-slate-400 text-xs">Prior Risk Events</div>
              <div className={`text-lg font-bold ${
                result.session_correlation.prior_risk_events > 0 ? 'text-cyber-amber' : 'text-cyber-green'
              }`}>
                {result.session_correlation.prior_risk_events}
              </div>
            </div>
            <div>
              <div className="text-slate-400 text-xs">Risk Boost</div>
              <div className="text-lg font-bold text-cyber-orange font-mono">
                +{result.session_correlation.session_risk_boost.toFixed(0)}
              </div>
            </div>
            <div>
              <div className="text-slate-400 text-xs">Escalation</div>
              <div className={`text-lg font-bold ${
                result.session_correlation.escalation_detected ? 'text-cyber-red' : 'text-cyber-green'
              }`}>
                {result.session_correlation.escalation_detected ? 'DETECTED' : 'None'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Workflow Nodes */}
      <div className="card">
        <div className="section-title">LangGraph Execution Path</div>
        <div className="space-y-2">
          {result.workflow_nodes.map((node, i) => (
            <div key={i} className="flex items-center gap-3 text-sm">
              <StatusDot status={node.status} />
              <span className="font-mono text-slate-200 w-48 flex-shrink-0">{node.name}</span>
              {node.duration_ms !== undefined && (
                <span className="text-slate-500 text-xs font-mono w-20 flex-shrink-0">
                  {node.duration_ms.toFixed(1)}ms
                </span>
              )}
              {node.detail && (
                <span className="text-slate-400 text-xs truncate">{node.detail}</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
