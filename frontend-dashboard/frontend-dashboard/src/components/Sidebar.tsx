import {
  LayoutDashboard,
  AlertTriangle,
  Shield,
  GitBranch,
  FileText,
  Globe,
  Settings,
  Users,
} from 'lucide-react';

const nav = [
  { icon: LayoutDashboard, label: 'Dashboard', active: true, badge: null },
  { icon: AlertTriangle, label: 'Alerts', active: false, badge: '23' },
  { icon: Shield, label: 'Incidents', active: false, badge: '4' },
  { icon: GitBranch, label: 'Playbooks', active: false, badge: null },
  { icon: Globe, label: 'Threat Intel', active: false, badge: null },
  { icon: Users, label: 'Assets', active: false, badge: null },
  { icon: FileText, label: 'Reports', active: false, badge: null },
];

const bottomNav = [{ icon: Settings, label: 'Settings' }];

export function Sidebar() {
  return (
    <aside className="hidden lg:flex w-48 shrink-0 flex-col border-r border-line bg-base-900">
      <nav className="flex-1 px-2 py-3 space-y-0.5">
        <p className="px-2 pb-1.5 pt-0.5 text-2xs font-semibold uppercase tracking-wider text-slate-600">
          Monitoring
        </p>
        {nav.map((item) => (
          <button
            key={item.label}
            className={`group flex w-full items-center gap-2.5 rounded-sm px-2 py-1.5 text-xs font-medium transition-colors border ${
              item.active
                ? 'bg-accent-600/10 text-accent-300 border-accent-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-base-850 border-transparent'
            }`}
          >
            <item.icon className="h-3.5 w-3.5 shrink-0" strokeWidth={1.75} />
            <span className="flex-1 text-left">{item.label}</span>
            {item.badge && (
              <span
                className={`tnum text-2xs font-semibold px-1 py-px rounded-sm ${
                  item.active
                    ? 'bg-accent-600/20 text-accent-300'
                    : 'bg-base-800 text-slate-500 group-hover:text-slate-400'
                }`}
              >
                {item.badge}
              </span>
            )}
          </button>
        ))}
      </nav>

      <div className="px-2 py-2 border-t border-line space-y-0.5">
        {bottomNav.map((item) => (
          <button
            key={item.label}
            className="flex w-full items-center gap-2.5 rounded-sm px-2 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-base-850 transition-colors"
          >
            <item.icon className="h-3.5 w-3.5 shrink-0" strokeWidth={1.75} />
            {item.label}
          </button>
        ))}
      </div>

      <div className="mx-2 mb-2 rounded-sm border border-line bg-base-850 p-2.5">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-2xs font-semibold uppercase tracking-wider text-slate-500">
            ML Engine
          </span>
          <span className="flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
        </div>
        <p className="text-2xs text-slate-500 leading-relaxed">
          Random Forest v2.3
        </p>
        <p className="text-2xs text-slate-600 mt-0.5">
          99.2% accuracy
        </p>
      </div>
    </aside>
  );
}
