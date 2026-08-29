import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { timelineData, severityMeta } from '@/data/mockData';

interface TooltipPayloadItem {
  dataKey: string;
  value: number;
  color: string;
}

function CustomTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipPayloadItem[];
  label?: string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const order = ['critical', 'high', 'medium', 'low'];
  const sorted = [...payload].sort(
    (a, b) => order.indexOf(a.dataKey) - order.indexOf(b.dataKey),
  );
  return (
    <div className="border border-line-strong bg-base-950 px-2.5 py-2">
      <p className="text-2xs font-semibold text-slate-400 mb-1.5">{label}</p>
      <div className="space-y-1">
        {sorted.map((p) => (
          <div key={p.dataKey} className="flex items-center gap-2">
            <span className="h-2 w-2" style={{ backgroundColor: p.color }} />
            <span className="text-2xs text-slate-500 capitalize flex-1">
              {p.dataKey}
            </span>
            <span className="tnum text-2xs font-semibold text-slate-300">
              {p.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AttackTimeline() {
  const colors = {
    critical: severityMeta.Critical.hex,
    high: severityMeta.High.hex,
    medium: severityMeta.Medium.hex,
    low: severityMeta.Low.hex,
  };
  const opacities = { critical: 0.18, high: 0.14, medium: 0.12, low: 0.10 };

  return (
    <div className="border border-line bg-base-900 p-3.5">
      <div className="flex items-center justify-between mb-2.5">
        <div>
          <h3 className="text-xs font-semibold text-slate-200">Attack Timeline</h3>
          <p className="text-2xs text-slate-600 mt-0.5">
            Alert volume by severity — last 7 days
          </p>
        </div>
        <div className="flex items-center gap-3 text-2xs">
          <span className="flex items-center gap-1.5 text-slate-500">
            <span className="h-2 w-2 bg-sev-critical" /> Critical
          </span>
          <span className="flex items-center gap-1.5 text-slate-500">
            <span className="h-2 w-2 bg-sev-high" /> High
          </span>
          <span className="flex items-center gap-1.5 text-slate-500">
            <span className="h-2 w-2 bg-sev-medium" /> Medium
          </span>
          <span className="flex items-center gap-1.5 text-slate-500">
            <span className="h-2 w-2 bg-sev-low" /> Low
          </span>
        </div>
      </div>

      <div className="h-[170px] -ml-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={timelineData} margin={{ top: 6, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1a2128" vertical={false} />
            <XAxis
              dataKey="day"
              tick={{ fill: '#566573', fontSize: 10 }}
              tickLine={false}
              axisLine={{ stroke: '#222b36' }}
              dy={4}
            />
            <YAxis
              tick={{ fill: '#566573', fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              width={26}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#303b48', strokeWidth: 1 }} />
            <Area type="monotone" dataKey="low" stackId="1" stroke={colors.low} strokeWidth={1} fill={colors.low} fillOpacity={opacities.low} />
            <Area type="monotone" dataKey="medium" stackId="1" stroke={colors.medium} strokeWidth={1} fill={colors.medium} fillOpacity={opacities.medium} />
            <Area type="monotone" dataKey="high" stackId="1" stroke={colors.high} strokeWidth={1} fill={colors.high} fillOpacity={opacities.high} />
            <Area type="monotone" dataKey="critical" stackId="1" stroke={colors.critical} strokeWidth={1} fill={colors.critical} fillOpacity={opacities.critical} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
