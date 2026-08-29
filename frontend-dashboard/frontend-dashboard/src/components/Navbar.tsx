import { Bell, Search, ChevronDown, Circle } from 'lucide-react';

export function Navbar() {
  return (
    <header className="h-12 shrink-0 border-b border-line bg-base-900 flex items-center justify-between px-4">
      {/* Brand — clean wordmark only */}
      <div className="flex items-center gap-4">
        <span className="text-[15px] font-semibold tracking-tight text-slate-200 leading-none">
          AI-SOAR
        </span>
        <span className="hidden sm:flex items-center gap-1.5 text-2xs font-medium text-emerald-500/80 pl-4 border-l border-line">
          <Circle className="h-1.5 w-1.5 fill-current" />
          Connected
        </span>
      </div>

      {/* Center search */}
      <div className="hidden lg:flex flex-1 max-w-sm mx-6">
        <div className="relative w-full">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search alerts, IPs, incidents…"
            className="w-full h-7 rounded-sm bg-base-850 border border-line pl-8 pr-3 text-xs text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-accent-600 transition-colors"
          />
          <kbd className="absolute right-2 top-1/2 -translate-y-1/2 hidden xl:inline-flex items-center rounded-sm border border-line bg-base-800 px-1 py-0.5 text-2xs text-slate-600 font-mono">
            ⌘K
          </kbd>
        </div>
      </div>

      {/* Right cluster */}
      <div className="flex items-center gap-2">
        <div className="hidden sm:flex items-center gap-1.5 px-2 h-7 rounded-sm border border-line bg-base-850">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-1.5 w-1.5 rounded-full bg-accent-400 opacity-50 animate-ping" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-accent-400" />
          </span>
          <span className="text-2xs font-medium text-slate-400">Live</span>
        </div>

        <button className="relative flex h-7 w-7 items-center justify-center rounded-sm border border-line bg-base-850 text-slate-400 hover:text-slate-200 hover:border-line-strong transition-colors">
          <Bell className="h-3.5 w-3.5" />
          <span className="absolute -top-1 -right-1 flex h-3.5 min-w-3.5 items-center justify-center rounded-full bg-sev-critical text-2xs font-semibold text-white px-0.5">
            7
          </span>
        </button>

        <div className="flex items-center gap-2 pl-2 ml-1 border-l border-line">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-base-700 border border-line-strong text-2xs font-semibold text-slate-300">
            AM
          </div>
          <div className="hidden md:flex flex-col leading-tight">
            <span className="text-xs font-medium text-slate-300">A. Morgan</span>
            <span className="text-2xs text-slate-600">Analyst L2</span>
          </div>
          <ChevronDown className="hidden md:block h-3 w-3 text-slate-600" />
        </div>
      </div>
    </header>
  );
}
