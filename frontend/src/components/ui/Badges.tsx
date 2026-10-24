import React from 'react';
import type { PolicyDecision, RiskCategory } from '../../types/api';

// ─── Risk Score Ring ──────────────────────────────────────────────────────────

interface RiskScoreRingProps {
  score: number;
  size?: number;
}

export const RiskScoreRing: React.FC<RiskScoreRingProps> = ({ score, size = 100 }) => {
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const filled = (score / 100) * circumference;

  const color =
    score >= 75 ? '#ef4444' :
    score >= 50 ? '#f97316' :
    score >= 25 ? '#f59e0b' :
    '#10b981';

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke="#1a2640" strokeWidth="8"
        />
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke={color} strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          className="score-ring"
          style={{ filter: `drop-shadow(0 0 6px ${color}80)` }}
        />
        <text
          x={size / 2} y={size / 2 + 1}
          textAnchor="middle" dominantBaseline="middle"
          fill={color} fontSize={size / 4} fontWeight="700" fontFamily="Inter"
        >
          {Math.round(score)}
        </text>
      </svg>
      <span className="text-xs text-slate-400">Risk Score</span>
    </div>
  );
};

// ─── Decision Badge ───────────────────────────────────────────────────────────

export const DecisionBadge: React.FC<{ decision: PolicyDecision; large?: boolean }> = ({ decision, large }) => {
  const classes = {
    ALLOW: 'badge-allow',
    QUARANTINE: 'badge-quarantine',
    BLOCK: 'badge-block',
  }[decision];

  return (
    <span className={`${classes} ${large ? 'text-sm px-3 py-1' : ''}`}>
      {decision === 'ALLOW' ? '✓ ' : decision === 'BLOCK' ? '✕ ' : '⚠ '}
      {decision}
    </span>
  );
};

// ─── Risk Category Badge ──────────────────────────────────────────────────────

export const RiskBadge: React.FC<{ category: RiskCategory }> = ({ category }) => {
  const classes = {
    LOW: 'badge-low',
    MEDIUM: 'badge-medium',
    HIGH: 'badge-high',
    CRITICAL: 'badge-critical',
  }[category];
  return <span className={classes}>{category}</span>;
};

// ─── Status Dot ───────────────────────────────────────────────────────────────

export const StatusDot: React.FC<{ status: string }> = ({ status }) => {
  const color =
    status === 'ran' || status === 'healthy' || status === 'operational' ? 'bg-cyber-green' :
    status === 'skipped' || status === 'degraded' ? 'bg-slate-500' :
    'bg-cyber-red';
  return <span className={`w-2 h-2 rounded-full ${color} flex-shrink-0 mt-0.5`} />;
};

// ─── Spinner ──────────────────────────────────────────────────────────────────

export const Spinner: React.FC<{ className?: string }> = ({ className = 'w-6 h-6' }) => (
  <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
  </svg>
);

// ─── Empty State ──────────────────────────────────────────────────────────────

export const EmptyState: React.FC<{ icon: string; title: string; desc: string }> = ({ icon, title, desc }) => (
  <div className="flex flex-col items-center justify-center py-16 text-center">
    <div className="text-5xl mb-4 opacity-40">{icon}</div>
    <h3 className="text-slate-300 font-semibold mb-2">{title}</h3>
    <p className="text-slate-500 text-sm max-w-xs">{desc}</p>
  </div>
);

// ─── Error Banner ─────────────────────────────────────────────────────────────

export const ErrorBanner: React.FC<{ message: string }> = ({ message }) => (
  <div className="bg-cyber-red/10 border border-cyber-red/30 rounded-lg px-4 py-3 text-cyber-red text-sm flex items-start gap-3">
    <span className="flex-shrink-0 mt-0.5">⚠</span>
    <span>{message}</span>
  </div>
);

// ─── Info Card ────────────────────────────────────────────────────────────────

export const InfoCard: React.FC<{ label: string; value: string | number; sub?: string; color?: string }> = ({
  label, value, sub, color = 'text-cyber-blue',
}) => (
  <div className="card">
    <div className="section-title">{label}</div>
    <div className={`text-2xl font-bold ${color}`}>{value}</div>
    {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
  </div>
);

// ─── Mode Badge ───────────────────────────────────────────────────────────────

export const ModeBadge: React.FC<{ mode: string }> = ({ mode }) => {
  const classes =
    mode === 'FULL' ? 'bg-cyber-green/10 text-cyber-green border-cyber-green/20' :
    mode === 'DEGRADED' ? 'bg-cyber-orange/10 text-cyber-orange border-cyber-orange/20' :
    'bg-slate-700 text-slate-400 border-slate-600';
  return (
    <span className={`badge border ${classes}`}>{mode}</span>
  );
};
