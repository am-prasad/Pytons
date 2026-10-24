import React, { useState, useEffect } from 'react';
import { AgentDemoPage } from './pages/AgentDemoPage';
import { OverviewPage } from './pages/OverviewPage';
import { PlaygroundPage } from './pages/PlaygroundPage';
import { ScenariosPage } from './pages/ScenariosPage';
import { TracesPage } from './pages/TracesPage';
import { EvaluationPage } from './pages/EvaluationPage';
import { HealthPage } from './pages/HealthPage';

type Page = 'demo' | 'overview' | 'playground' | 'scenarios' | 'traces' | 'evaluation' | 'health';

interface NavItem {
  id: Page;
  code: string;
  label: string;
  desc: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'demo', code: '01', label: 'Live Demo', desc: 'Document upload & dual agents' },
  { id: 'overview', code: '02', label: 'Overview', desc: 'System dashboard & telemetry' },
  { id: 'playground', code: '03', label: 'Playground', desc: 'Inspect prompts & payloads' },
  { id: 'scenarios', code: '04', label: 'Scenarios', desc: 'Curated test cases' },
  { id: 'traces', code: '05', label: 'Traces', desc: 'Audit log & execution nodes' },
  { id: 'evaluation', code: '06', label: 'Evaluation', desc: 'Recall & precision lab' },
  { id: 'health', code: '07', label: 'Health', desc: 'Pipeline components status' },
];

function App() {
  const [page, setPage] = useState<Page>('demo');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('agentshield-theme');
    if (saved === 'dark' || saved === 'light') return saved;
    return 'light'; // default to clean light mode
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('agentshield-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'light' ? 'dark' : 'light'));
  };

  const renderPage = () => {
    switch (page) {
      case 'demo': return <AgentDemoPage />;
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
    <div className="flex h-screen overflow-hidden bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans transition-colors duration-150">
      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 z-50 w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col
        transition-transform duration-200
        ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        {/* Header / Brand */}
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-base font-bold tracking-tight text-slate-900 dark:text-slate-100">
                AgentShield
              </div>
              <div className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
                Runtime Security Layer
              </div>
            </div>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
              v1.0
            </span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-3 space-y-1 overflow-y-auto">
          <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
            Console
          </div>
          {NAV_ITEMS.map(item => {
            const isActive = page === item.id;
            return (
              <button
                key={item.id}
                id={`nav-${item.id}`}
                onClick={() => navigate(item.id)}
                className={isActive ? 'nav-item-active w-full text-left' : 'nav-item-inactive w-full text-left'}
              >
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500">
                    {item.code}
                  </span>
                  <div>
                    <div className="text-sm font-medium leading-snug">{item.label}</div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400 font-normal">{item.desc}</div>
                  </div>
                </div>
              </button>
            );
          })}
        </nav>

        {/* Sidebar Footer */}
        <div className="p-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
          {/* Theme switcher */}
          <button
            onClick={toggleTheme}
            id="theme-toggle-btn"
            className="w-full flex items-center justify-between px-3 py-1.5 rounded-md border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 text-xs text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <span className="font-medium">Appearance</span>
            <span className="font-mono text-[11px] uppercase tracking-wider font-semibold text-slate-500 dark:text-slate-400">
              {theme === 'light' ? 'Light Mode' : 'Dark Mode'}
            </span>
          </button>

          <div className="px-1 text-[11px] text-slate-400 dark:text-slate-500 leading-tight">
            Team Pytons · Hackathon MVP
          </div>
        </div>
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/30 dark:bg-black/60 lg:hidden backdrop-blur-xs"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-h-screen overflow-hidden">
        {/* Top Header */}
        <header className="h-12 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-4 lg:px-6 flex-shrink-0">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="lg:hidden p-1.5 rounded text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
              aria-label="Toggle navigation"
            >
              <div className="w-4 h-0.5 bg-current mb-1" />
              <div className="w-4 h-0.5 bg-current mb-1" />
              <div className="w-4 h-0.5 bg-current" />
            </button>
            <div className="text-sm font-semibold text-slate-800 dark:text-slate-200">
              {NAV_ITEMS.find(n => n.id === page)?.label}
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-600 dark:bg-emerald-400" />
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400">
                Policy Enforcement Active
              </span>
            </div>

            <button
              onClick={toggleTheme}
              className="hidden sm:inline-flex items-center px-2.5 py-1 text-xs font-medium rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
            >
              {theme === 'light' ? 'Switch to Dark' : 'Switch to Light'}
            </button>
          </div>
        </header>

        {/* Page View */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          <div className="max-w-6xl mx-auto">
            {renderPage()}
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
