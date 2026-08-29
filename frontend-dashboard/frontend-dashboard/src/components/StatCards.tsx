import {
  Bell,
  AlertOctagon,
  Crosshair,
  Timer,
  ArrowUpRight,
  ArrowDownRight,
} from 'lucide-react';
import { stats } from '@/data/mockData';

const iconMap = { Bell, AlertOctagon, Crosshair, Timer };

export function StatCards() {
  return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-2.5">
      {stats.map((s) => {
        const Icon = iconMap[s.icon as keyof typeof iconMap];
        const TrendIcon = s.trend === 'up' ? ArrowUpRight : ArrowDownRight;
        const deltaColor = s.deltaNegative
          ? 'text-sev-critical'
          : 'text-emerald-500/90';
        return (
          <div
            key={s.id}
            className="border border-line bg-base-900 px-3.5 py-3"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Icon className="h-3.5 w-3.5 text-slate-500" strokeWidth={1.75} />
                <span className="text-2xs font-medium uppercase tracking-wider text-slate-500">
                  {s.label}
                </span>
              </div>
              <span className={`tnum flex items-center gap-0.5 text-2xs font-semibold ${deltaColor}`}>
                <TrendIcon className="h-2.5 w-2.5" />
                {s.delta}
              </span>
            </div>
            <div className="tnum text-xl font-semibold text-slate-200 leading-none">
              {s.value}
            </div>
            <p className="text-2xs text-slate-600 mt-1.5">{s.sub}</p>
          </div>
        );
      })}
    </div>
  );
}
