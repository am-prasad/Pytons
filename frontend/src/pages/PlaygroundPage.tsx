import React, { useState } from 'react';
import type { AnalyzeResponse, SourceType } from '../types/api';
import { analyzeInput, resetSession } from '../services/api';
import { ATTACK_SCENARIOS } from '../services/scenarios';
import { ResultsPanel } from '../components/ResultsPanel';
import { Spinner, ErrorBanner, DecisionBadge } from '../components/ui/Badges';

const SOURCE_TYPES: { value: SourceType; label: string }[] = [
  { value: 'user_prompt', label: 'User Prompt' },
  { value: 'retrieved_document', label: 'Retrieved Document' },
  { value: 'web_content', label: 'Web Content' },
  { value: 'tool_output', label: 'Tool Output' },
  { value: 'conversation_history', label: 'Conversation History' },
];

export const PlaygroundPage: React.FC = () => {
  const [text, setText] = useState('');
  const [sourceType, setSourceType] = useState<SourceType>('user_prompt');
  const [sessionId, setSessionId] = useState('demo-session-1');
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
      const msg = e instanceof Error ? e.message : 'Failed to reach backend. Ensure the server is running.';
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
      try { await resetSession(sessionId); } catch {}
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white glow-text-blue mb-1">Security Playground</h1>
        <p className="text-slate-400 text-sm">
          Submit prompts, documents, or tool outputs through the AgentShield security pipeline.
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="space-y-4">
          {/* Scenario Selector */}
          <div className="card">
            <div className="section-title">Quick Scenarios</div>
            <div className="grid grid-cols-1 gap-2">
              {ATTACK_SCENARIOS.map(s => (
                <button
                  key={s.id}
                  id={`scenario-${s.id}`}
                  onClick={() => handleScenarioSelect(s.id)}
                  className={`text-left px-3 py-2.5 rounded-lg border text-sm transition-all ${
                    selectedScenario === s.id
                      ? 'border-cyber-blue/50 bg-cyber-blue/5 text-slate-200'
                      : 'border-navy-600 hover:border-navy-500 text-slate-400 hover:text-slate-300'
                  }`}
                >
                  <div className="font-medium">{s.name}</div>
                  <div className="text-xs text-slate-500 mt-0.5 truncate">{s.description}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Input Form */}
          <div className="card space-y-4">
            <div>
              <label className="section-title block">Input Text</label>
              <textarea
                id="input-text"
                value={text}
                onChange={e => setText(e.target.value)}
                placeholder="Enter prompt, document content, tool output, or web content..."
                rows={8}
                className="input-field resize-none"
                maxLength={8000}
              />
              <div className="text-right text-xs text-slate-500 mt-1">{text.length} / 8000</div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="section-title block">Source Type</label>
                <select
                  id="source-type-select"
                  value={sourceType}
                  onChange={e => setSourceType(e.target.value as SourceType)}
                  className="select-field"
                >
                  {SOURCE_TYPES.map(s => (
                    <option key={s.value} value={s.value}>{s.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="section-title block">Session ID</label>
                <input
                  id="session-id-input"
                  type="text"
                  value={sessionId}
                  onChange={e => setSessionId(e.target.value)}
                  placeholder="Optional session ID"
                  className="input-field"
                  maxLength={64}
                />
              </div>
            </div>

            <div className="flex gap-3">
              <button
                id="analyze-btn"
                onClick={handleAnalyze}
                disabled={loading || !text.trim()}
                className="btn-primary flex-1 flex items-center justify-center gap-2"
              >
                {loading ? (
                  <><Spinner className="w-4 h-4" /> Analyzing...</>
                ) : (
                  <><span></span> Analyze</>
                )}
              </button>
              <button
                id="reset-btn"
                onClick={handleReset}
                className="btn-ghost"
              >
                Reset
              </button>
            </div>

            {error && <ErrorBanner message={error} />}
          </div>
        </div>

        {/* Results Panel */}
        <div>
          {loading && (
            <div className="card-cyber flex flex-col items-center justify-center py-20 gap-4">
              <div className="relative">
                <Spinner className="w-12 h-12 text-cyber-blue" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="w-4 h-4 bg-cyber-blue/30 rounded-full animate-pulse" />
                </div>
              </div>
              <div className="text-center">
                <div className="text-slate-300 font-semibold">Running Security Pipeline</div>
                <div className="text-slate-500 text-sm mt-1">Scanning → Analyzing → Policy Gate...</div>
              </div>
            </div>
          )}

          {!loading && !result && !error && (
            <div className="card-cyber flex flex-col items-center justify-center py-20 text-center gap-4">
              <div className="text-6xl opacity-20">🛡</div>
              <div>
                <div className="text-slate-300 font-semibold">Ready to Analyze</div>
                <div className="text-slate-500 text-sm mt-1">
                  Select a scenario or enter custom input, then click Analyze.
                </div>
              </div>
            </div>
          )}

          {!loading && result && <ResultsPanel result={result} />}
        </div>
      </div>
    </div>
  );
};
