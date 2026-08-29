import { Navbar } from '@/components/Navbar';
import { Sidebar } from '@/components/Sidebar';
import { StatCards } from '@/components/StatCards';
import { SeverityChart } from '@/components/SeverityChart';
import { AttackTimeline } from '@/components/AttackTimeline';
import { AlertsTable } from '@/components/AlertsTable';
import { TopAttackingIps } from '@/components/TopAttackingIps';
import { MitrePanel } from '@/components/MitrePanel';
import { SlidersHorizontal, RefreshCw, Download } from 'lucide-react';

function App() {
  return (
    <div className="flex h-screen flex-col overflow-hidden bg-base-950 text-slate-300">
      <Navbar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto">
          {/* Page header */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-line bg-base-900/40">
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold text-slate-200">Operations Dashboard</h1>
                <span className="border border-line bg-base-850 px-1.5 py-px text-2xs font-mono text-slate-600">
                  v2.3.1
                </span>
              </div>
              <p className="text-2xs text-slate-600 mt-0.5">
                Real-time monitoring · Auto-refresh 30s · Last update 09:42:18 UTC
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              <button className="flex items-center gap-1.5 border border-line bg-base-850 px-2.5 py-1 text-2xs font-medium text-slate-400 hover:text-slate-200 hover:border-line-strong transition-colors">
                <SlidersHorizontal className="h-3 w-3" strokeWidth={1.75} />
                Filters
              </button>
              <button className="flex items-center gap-1.5 border border-line bg-base-850 px-2.5 py-1 text-2xs font-medium text-slate-400 hover:text-slate-200 hover:border-line-strong transition-colors">
                <RefreshCw className="h-3 w-3" strokeWidth={1.75} />
                Refresh
              </button>
              <button className="flex items-center gap-1.5 border border-accent-600/40 bg-accent-600/10 px-2.5 py-1 text-2xs font-medium text-accent-300 hover:bg-accent-600/20 transition-colors">
                <Download className="h-3 w-3" strokeWidth={1.75} />
                Export
              </button>
            </div>
          </div>

          {/* Dashboard body */}
          <div className="p-3 space-y-3">
            <StatCards />

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
              <div className="xl:col-span-2">
                <AttackTimeline />
              </div>
              <SeverityChart />
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
              <div className="xl:col-span-2">
                <AlertsTable />
              </div>
              <div className="space-y-3">
                <TopAttackingIps />
                <MitrePanel />
              </div>
            </div>

            <footer className="flex items-center justify-between pt-1 pb-0.5 text-2xs text-slate-700">
              <span>AI-SOAR Platform · Final Year Project Demo</span>
              <span className="font-mono">Session: 0a4f-29b1-ec72</span>
            </footer>
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
