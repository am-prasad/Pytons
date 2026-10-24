import React, { useState } from 'react';
import { OverviewPage } from './pages/OverviewPage';
import { PlaygroundPage } from './pages/PlaygroundPage';
import { ScenariosPage } from './pages/ScenariosPage';
import { TracesPage } from './pages/TracesPage';
import { EvaluationPage } from './pages/EvaluationPage';
import { HealthPage } from './pages/HealthPage';

type Page = 'overview' | 'playground' | 'scenarios' | 'traces' | 'evaluation' | 'health';

const NAV_ITEMS: { id: Page; label: string; icon: string; desc: string }[] = [
  { id: 'overview', label: 'Overview', icon: '⬡', desc: 'Dashboard' },
  { id: 'playground', label: 'Security Playground', icon: '🔬', desc: 'Analyze inputs' },
  { id: 'scenarios', label: 'Attack Scenarios', icon: '⚔', desc: 'Preset demos' },
  { id: 'traces', label: 'Execution Traces', icon: '📋', desc: 'Audit trail' },
  { id: 'evaluation', label: 'Evaluation Lab', icon: '📊', desc: 'Metrics' },
  { id: 'health', label: 'System Health', icon: '💚', desc: 'Component status' },
];

function App() {
  const [page, setPage] = useState<Page>('overview');
  const [mobileOpen, setMobileOpen] = useState(false);

  const renderPage = () => {
    switch (page) {
      case 'overview': return <OverviewPage />;
      case 'playground': return <PlaygroundPage />;
      case 'scenarios': return <ScenariosPage />;
      case 'traces': return <TracesPage />;
      case 'evaluation': return <EvaluationPage />;
      case 'health': return <HealthPage />;
    }
  };

  const navigate = (p: Page) => {
    setPage(p);
    setMobileOpen(false);
  };

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 z-50 w-64 bg-navy-900 border-r border-navy-700 flex flex-col
        transition-transform duration-300
        ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        {/* Logo */}
        <div className="px-5 py-5 border-b border-navy-700">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center text-xl">
              🛡
            </div>
            <div>
              <div className="font-bold text-white leading-tight glow-text-blue">AgentShield</div>
              <div className="text-xs text-slate-500">AI Security Platform</div>
            </div>
          </div>
        </div>

        {/* Nav Items */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              id={`nav-${item.id}`}
              onClick={() => navigate(item.id)}
              className={page === item.id ? 'nav-item-active w-full' : 'nav-item-inactive w-full'}
            >
              <span className="text-base w-6 flex-shrink-0">{item.icon}</span>
              <div className="text-left">
                <div className="text-sm font-medium">{item.label}</div>
                <div className="text-xs opacity-60">{item.desc}</div>
              </div>
            </button>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-4 py-4 border-t border-navy-700">
          <div className="text-xs text-slate-500 text-center">
            Team Pytons · AgentShield v1.0
          </div>
          <div className="text-xs text-slate-600 text-center mt-1">
            MVP prototype · not production ready
          </div>
        </div>
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main content */}
      <div className="flex-1 lg:pl-64 flex flex-col min-h-screen overflow-hidden">
        {/* Top bar */}
        <header className="flex-shrink-0 h-14 bg-navy-900 border-b border-navy-700 flex items-center px-4 gap-4">
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="lg:hidden text-slate-400 hover:text-white p-1"
          >
            ☰
          </button>
          <div className="text-sm font-semibold text-white capitalize">
            {NAV_ITEMS.find(n => n.id === page)?.label}
          </div>
          <div className="ml-auto flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
            <span className="text-xs text-slate-400">AgentShield Active</span>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-5 lg:p-6">
          {renderPage()}
        </main>
      </div>
    </div>
  );
}

export default App;
