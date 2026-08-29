import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { severityCounts, severityMeta } from '@/data/mockData';
import type { Severity } from '@/data/mockData';

const data: { name: Severity; value: number; color: string }[] = [
  { name: 'Critical', value: severityCounts.Critical, color: severityMeta.Critical.hex },
  { name: 'High', value: severityCounts.High, color: severityMeta.High.hex },
  { name: 'Medium', value: severityCounts.Medium, color: severityMeta.Medium.hex },
  { name: 'Low', value: severityCounts.Low, color: severityMeta.Low.hex },
];

const total = data.reduce((sum, d) => sum + d.value, 0);

export function SeverityChart() {
  return (
    <div className="border border-line bg-base-900 p-3.5">
      <div className="flex items-center justify-between mb-2.5">
        <div>
          <h3 className="text-xs font-semibold text-slate-200">Severity Breakdown</h3>
          <p className="text-2xs text-slate-600 mt-0.5">Alerts by classification</p>
        </div>
        <span className="text-2xs text-slate-600 font-mono">7d</span>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative h-[120px] w-[120px] shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={36}
                outerRadius={54}
                paddingAngle={1.5}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="tnum text-base font-semibold text-slate-200 leading-none">
              {total.toLocaleString()}
            </span>
            <span className="text-2xs text-slate-600 mt-0.5">Total</span>
          </div>
        </div>

        <div className="flex-1 space-y-1.5">
          {data.map((d) => {
            const meta = severityMeta[d.name];
            const pct = ((d.value / total) * 100).toFixed(1);
            return (
              <div key={d.name} className="flex items-center gap-2.5">
                <span className={`h-2 w-2 ${meta.dot}`} />
                <span className="text-2xs text-slate-400 flex-1">{d.name}</span>
                <span className="tnum text-xs font-semibold text-slate-300">
                  {d.value}
                </span>
                <span className="tnum text-2xs text-slate-600 w-9 text-right">
                  {pct}%
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
