import React, { useState } from 'react';
import type { AnalyzeResponse, SourceType } from '../types/api';
import { analyzeInput, resetSession } from '../services/api';
import { ATTACK_SCENARIOS } from '../services/scenarios';
import { ResultsPanel } from '../components/ResultsPanel';
import { Spinner, ErrorBanner } from '../components/ui/Badges';

const SOURCE_TYPES: { value: SourceType; label: string }[] = [
  { value: 'user_prompt', label: 'User Prompt (1.0x)' },
  { value: 'retrieved_document', label: 'Retrieved Document / RAG (1.15x)' },
  { value: 'web_content', label: 'Web Scraping (1.15x)' },
  { value: 'tool_output', label: 'Tool Output (1.10x)' },
  { value: 'conversation_history', label: 'Conversation History (1.05x)' },
];

export const PlaygroundPage: React.FC = () => {
  const [text, setText] = useState('');
  const [sourceType, setSourceType] = useState<SourceType>('user_prompt');
  const [sessionId, setSessionId] = useState('demo-session-01');
  const [selectedScenario, setSelectedScenario] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);

  const handleScenarioSelect = (id: string) => {
    const scenario = ATTACK_SCENARIOS.find(s => s.id === id);
    if (scenario) {
      setSelectedScenario(id);
      setText(scenario.text);
      setSourceType(scenario.source_type);
    }
  };

  const handleAnalyze = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await analyzeInput({
        text,
        source_type: sourceType,
        session_id: sessionId || undefined,
        scenario_id: selectedScenario || undefined,
      });
      setResult(res);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Analysis failed. Confirm backend is online.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    setText('');
    setSourceType('user_prompt');
    setSelectedScenario('');
    setResult(null);
    setError(null);
    if (sessionId) {
      try {
        await resetSession(sessionId);
      } catch {}
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          Security Playground
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Inspect and evaluate prompts, retrieved documents, and tool responses through the multi-layer security pipeline.
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6 items-start">
        {/* Left Column: Scenarios & Input Form */}
        <div className="space-y-4">
          {/* Quick Scenario Selector */}
          <div className="card">
            <div className="section-title">Pre-Configured Scenarios</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
              {ATTACK_SCENARIOS.map(s => {
                const isSelected = selectedScenario === s.id;
                return (
                  <button
                    key={s.id}
                    id={`scenario-${s.id}`}
                    onClick={() => handleScenarioSelect(s.id)}
                    className={`text-left p-2.5 rounded-md border text-xs transition-colors ${
                      isSelected
                        ? 'border-slate-900 bg-slate-900 text-white dark:border-slate-100 dark:bg-slate-100 dark:text-slate-900'
                        : 'border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/40 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                  >
                    <div className="font-semibold">{s.name}</div>
                    <div className={`text-[11px] mt-0.5 line-clamp-1 ${
                      isSelected ? 'text-slate-200 dark:text-slate-700' : 'text-slate-500 dark:text-slate-400'
                    }`}>
                      {s.description}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Input Form */}
          <div className="card space-y-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="input-text" className="section-title mb-0">
                  Input Content
                </label>
                <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500">
                  {text.length} / 8,000 chars
                </span>
              </div>
              <textarea
                id="input-text"
                value={text}
                onChange={e => setText(e.target.value)}
                placeholder="Enter prompt text, retrieved RAG content, or simulated tool payload..."
                rows={7}
                className="input-field font-mono text-xs leading-relaxed resize-none"
                maxLength={8000}
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="source-type-select" className="section-title block">
                  Source Provenance
                </label>
                <select
                  id="source-type-select"
                  value={sourceType}
                  onChange={e => setSourceType(e.target.value as SourceType)}
                  className="select-field text-xs"
                >
                  {SOURCE_TYPES.map(s => (
                    <option key={s.value} value={s.value}>{s.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="session-id-input" className="section-title block">
                  Session Key
                </label>
                <input
                  id="session-id-input"
                  type="text"
                  value={sessionId}
                  onChange={e => setSessionId(e.target.value)}
                  placeholder="e.g. user-session-101"
                  className="input-field text-xs font-mono"
                  maxLength={64}
                />
              </div>
            </div>

            <div className="flex gap-2.5 pt-1">
              <button
                id="analyze-btn"
                onClick={handleAnalyze}
                disabled={loading || !text.trim()}
                className="btn-primary flex-1 flex items-center justify-center gap-2"
              >
                {loading && <Spinner className="w-3.5 h-3.5" />}
                <span>{loading ? 'Evaluating Pipeline...' : 'Run Security Pipeline'}</span>
              </button>

              <button
                id="reset-btn"
                onClick={handleReset}
                disabled={loading}
                className="btn-ghost"
              >
                Reset
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Output / Findings Panel */}
        <div className="space-y-4">
          {error && <ErrorBanner message={error} />}

          {result ? (
            <ResultsPanel result={result} />
          ) : (
            <div className="card text-center py-16 px-4">
              <div className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-1">
                Awaiting Analysis
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto leading-relaxed">
                Select a scenario above or enter untrusted content to observe multi-layer scanning, Groq contextual judging, and deterministic policy decisions.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
