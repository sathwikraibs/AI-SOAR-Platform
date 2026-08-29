import { Globe } from 'lucide-react';
import { attackingIps, severityMeta } from '@/data/mockData';

export function TopAttackingIps() {
  const max = attackingIps[0]?.count ?? 1;
  return (
    <div className="border border-line bg-base-900 p-3.5">
      <div className="flex items-center justify-between mb-2.5">
        <div>
          <h3 className="text-xs font-semibold text-slate-200">Top Attacking IPs</h3>
          <p className="text-2xs text-slate-600 mt-0.5">By alert volume — 7d</p>
        </div>
        <Globe className="h-3.5 w-3.5 text-slate-600" strokeWidth={1.75} />
      </div>

      <div className="space-y-1">
        {attackingIps.slice(0, 7).map((ip) => {
          const meta = severityMeta[ip.topSeverity];
          const pct = (ip.count / max) * 100;
          return (
            <div
              key={ip.ip}
              className="group flex items-center gap-2.5 px-1.5 py-1.5 hover:bg-base-850 transition-colors"
            >
              <span className="tnum font-mono text-2xs text-slate-300 w-[110px] shrink-0">
                {ip.ip}
              </span>
              <div className="flex-1 relative h-4 bg-base-850">
                <div
                  className="absolute inset-y-0 left-0 opacity-25"
                  style={{ width: `${pct}%`, backgroundColor: meta.hex }}
                />
                <div className="absolute inset-0 flex items-center px-2">
                  <span className="text-2xs text-slate-600 group-hover:text-slate-500">
                    {ip.country}
                  </span>
                </div>
              </div>
              <span
                className="tnum text-2xs font-semibold w-5 text-right"
                style={{ color: meta.hex }}
              >
                {ip.count}
              </span>
              <span className="text-2xs text-slate-700 font-mono w-6 text-right">
                {ip.flag}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
