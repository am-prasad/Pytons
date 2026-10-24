import React from 'react';
import type { PolicyDecision, RiskCategory } from '../../types/api';

// ─── Risk Score Gauge ─────────────────────────────────────────────────────────

interface RiskScoreRingProps {
  score: number;
  size?: number;
}

export const RiskScoreRing: React.FC<RiskScoreRingProps> = ({ score, size = 96 }) => {
  const strokeWidth = 8;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const filled = Math.min(100, Math.max(0, score)) / 100 * circumference;

  const color =
    score >= 75 ? '#e11d48' : // rose-600
    score >= 50 ? '#ea580c' : // orange-600
    score >= 25 ? '#d97706' : // amber-600
    '#059669'; // emerald-600

  return (
    <div className="flex flex-col items-center justify-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="score-ring">
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-slate-200 dark:text-slate-800"
        />
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
        />
      </svg>
      <div className="text-center -mt-[64px] mb-4">
        <div className="font-mono text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          {Math.round(score)}
        </div>
        <div className="text-[10px] uppercase font-semibold tracking-wider text-slate-500 dark:text-slate-400">
          Score
        </div>
      </div>
    </div>
  );
};

// ─── Decision Badge ───────────────────────────────────────────────────────────

export const DecisionBadge: React.FC<{ decision: PolicyDecision; large?: boolean }> = ({ decision, large }) => {
  const baseClasses = large ? 'text-xs px-3 py-1 font-semibold tracking-wider' : 'text-[11px] px-2 py-0.5 font-medium';

  const variantClasses = {
    ALLOW: 'bg-emerald-50 text-emerald-800 border border-emerald-200 dark:bg-emerald-950/70 dark:text-emerald-300 dark:border-emerald-800',
    QUARANTINE: 'bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800',
    BLOCK: 'bg-rose-50 text-rose-800 border border-rose-200 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800',
  }[decision] || 'bg-slate-100 text-slate-700 border border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700';

  return (
    <span className={`inline-flex items-center rounded uppercase ${baseClasses} ${variantClasses}`}>
      {decision}
    </span>
  );
};

// ─── Risk Category Badge ──────────────────────────────────────────────────────

export const RiskBadge: React.FC<{ category: RiskCategory }> = ({ category }) => {
  const variantClasses = {
    LOW: 'text-emerald-700 bg-emerald-50 border-emerald-200 dark:text-emerald-400 dark:bg-emerald-950/50 dark:border-emerald-800',
    MEDIUM: 'text-amber-700 bg-amber-50 border-amber-200 dark:text-amber-400 dark:bg-amber-950/50 dark:border-amber-800',
    HIGH: 'text-orange-700 bg-orange-50 border-orange-200 dark:text-orange-400 dark:bg-orange-950/50 dark:border-orange-800',
    CRITICAL: 'text-rose-700 bg-rose-50 border-rose-200 dark:text-rose-400 dark:bg-rose-950/50 dark:border-rose-800',
  }[category] || 'text-slate-700 bg-slate-100 border-slate-200 dark:text-slate-300 dark:bg-slate-800 dark:border-slate-700';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider border ${variantClasses}`}>
      {category}
    </span>
  );
};

// ─── Status Dot ───────────────────────────────────────────────────────────────

export const StatusDot: React.FC<{ status: string }> = ({ status }) => {
  const isGood = status === 'ran' || status === 'healthy' || status === 'operational' || status === 'ready';
  const isWarn = status === 'skipped' || status === 'degraded' || status === 'quarantined';

  const dotClass = isGood
    ? 'bg-emerald-600 dark:bg-emerald-400'
    : isWarn
    ? 'bg-amber-500 dark:bg-amber-400'
    : 'bg-rose-600 dark:bg-rose-400';

  return <span className={`w-2 h-2 rounded-full ${dotClass} flex-shrink-0`} />;
};

// ─── Spinner ──────────────────────────────────────────────────────────────────

export const Spinner: React.FC<{ className?: string }> = ({ className = 'w-4 h-4' }) => (
  <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
  </svg>
);

// ─── Empty State ──────────────────────────────────────────────────────────────

export const EmptyState: React.FC<{ title: string; desc: string }> = ({ title, desc }) => (
  <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
    <div className="w-10 h-10 rounded-full border border-slate-300 dark:border-slate-700 flex items-center justify-center text-slate-400 mb-3">
      <div className="w-2 h-2 rounded-full bg-slate-400" />
    </div>
    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">{title}</h3>
    <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm">{desc}</p>
  </div>
);

// ─── Error Banner ─────────────────────────────────────────────────────────────

export const ErrorBanner: React.FC<{ message: string }> = ({ message }) => (
  <div className="bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 rounded-md p-3 text-rose-800 dark:text-rose-300 text-xs flex items-start gap-2.5">
    <span className="font-semibold uppercase tracking-wider text-[10px] bg-rose-200 dark:bg-rose-900 px-1.5 py-0.5 rounded">Error</span>
    <span className="leading-relaxed">{message}</span>
  </div>
);

// ─── Info Card ────────────────────────────────────────────────────────────────

export const InfoCard: React.FC<{
  label: string;
  value: string | number;
  sub?: string;
  badge?: string;
}> = ({ label, value, sub, badge }) => (
  <div className="card">
    <div className="flex items-center justify-between mb-2">
      <span className="section-title mb-0">{label}</span>
      {badge && (
        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
          {badge}
        </span>
      )}
    </div>
    <div className="font-mono text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
      {value}
    </div>
    {sub && <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">{sub}</div>}
  </div>
);

// ─── Mode Badge ───────────────────────────────────────────────────────────────

export const ModeBadge: React.FC<{ mode: string }> = ({ mode }) => {
  const isFull = mode === 'FULL';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold uppercase tracking-wider border ${
      isFull
        ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800'
        : 'bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
    }`}>
      {mode}
    </span>
  );
};
