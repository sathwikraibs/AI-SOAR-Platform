import { useState } from 'react';
import { Ban, UserX, BellRing, Boxes, MoreHorizontal, ArrowUpDown } from 'lucide-react';
import { alerts, severityMeta, statusMeta } from '@/data/mockData';
import type { ResponseAction, Severity } from '@/data/mockData';

const actionIcons: Record<ResponseAction, typeof Ban> = {
  'Block IP': Ban,
  'Disable User': UserX,
  'Notify Admin': BellRing,
  Quarantine: Boxes,
};

const severityFilters: (Severity | 'All')[] = ['All', 'Critical', 'High', 'Medium', 'Low'];

function fmtTime(iso: string): string {
  const d = new Date(iso);
  const now = new Date('2026-08-29T09:42:00');
  const diff = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function fmtFull(iso: string): string {
  return new Date(iso).toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function AlertsTable() {
  const [filter, setFilter] = useState<Severity | 'All'>('All');

  const filtered =
    filter === 'All' ? alerts : alerts.filter((a) => a.severity === filter);

  return (
    <div className="border border-line bg-base-900">
      <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-line">
        <div className="flex items-center gap-2.5">
          <h3 className="text-xs font-semibold text-slate-200">Live Alerts</h3>
          <span className="flex items-center gap-1.5 text-2xs text-emerald-500/80">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500 opacity-50 animate-ping" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
            </span>
            Streaming
          </span>
        </div>

        <div className="flex items-center gap-px">
          {severityFilters.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-2 py-1 text-2xs font-medium transition-colors border ${
                filter === f
                  ? 'bg-base-800 text-slate-200 border-line-strong'
                  : 'text-slate-500 hover:text-slate-300 border-transparent'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-line text-2xs uppercase tracking-wider text-slate-600">
              <th className="text-left font-semibold px-3.5 py-2 w-[145px]">
                <button className="flex items-center gap-1 hover:text-slate-400">
                  Timestamp <ArrowUpDown className="h-2.5 w-2.5" />
                </button>
              </th>
              <th className="text-left font-semibold px-2.5 py-2">Source IP</th>
              <th className="text-left font-semibold px-2.5 py-2">Alert Type</th>
              <th className="text-left font-semibold px-2.5 py-2 w-[85px]">Severity</th>
              <th className="text-left font-semibold px-2.5 py-2 w-[115px]">Status</th>
              <th className="text-left font-semibold px-2.5 py-2 w-[130px]">Action</th>
              <th className="w-7 px-1.5" />
            </tr>
          </thead>
          <tbody>
            {filtered.map((a, i) => {
              const sevM = severityMeta[a.severity];
              const stM = statusMeta[a.status];
              const ActionIcon = a.action ? actionIcons[a.action] : null;
              return (
                <tr
                  key={a.id}
                  className={`border-b border-line/50 hover:bg-base-850/50 transition-colors ${
                    i % 2 === 1 ? 'bg-base-900/30' : ''
                  }`}
                >
                  <td className="px-3.5 py-2">
                    <div className="flex flex-col leading-tight">
                      <span className="text-slate-300 font-mono text-2xs">
                        {fmtFull(a.timestamp)}
                      </span>
                      <span className="text-2xs text-slate-600">{fmtTime(a.timestamp)}</span>
                    </div>
                  </td>
                  <td className="px-2.5 py-2">
                    <div className="flex flex-col leading-tight">
                      <span className="font-mono text-slate-300">{a.sourceIp}</span>
                      <span className="text-2xs text-slate-600">{a.country}</span>
                    </div>
                  </td>
                  <td className="px-2.5 py-2">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-200">{a.alertType}</span>
                      <span className="font-mono text-2xs text-slate-600 bg-base-850 border border-line px-1 py-px">
                        {a.mitreId}
                      </span>
                    </div>
                  </td>
                  <td className="px-2.5 py-2">
                    <span className="flex items-center gap-1.5">
                      <span className={`h-2 w-2 ${sevM.dot}`} />
                      <span className={`text-2xs font-medium ${sevM.text}`}>
                        {a.severity}
                      </span>
                    </span>
                  </td>
                  <td className="px-2.5 py-2">
                    <span className="flex items-center gap-1.5">
                      <span className={`h-2 w-2 ${stM.dot}`} />
                      <span className={`text-2xs font-medium ${stM.text}`}>
                        {a.status}
                      </span>
                    </span>
                  </td>
                  <td className="px-2.5 py-2">
                    {ActionIcon && a.action ? (
                      <button className="inline-flex items-center gap-1.5 border border-line bg-base-850 px-2 py-1 text-2xs font-medium text-slate-400 hover:border-accent-600/40 hover:text-accent-300 transition-colors">
                        <ActionIcon className="h-3 w-3" strokeWidth={1.75} />
                        {a.action}
                      </button>
                    ) : (
                      <span className="text-2xs text-slate-700">—</span>
                    )}
                  </td>
                  <td className="px-1.5 py-2 text-right">
                    <button className="text-slate-700 hover:text-slate-400">
                      <MoreHorizontal className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between px-3.5 py-2 border-t border-line">
        <span className="text-2xs text-slate-600">
          Showing <span className="tnum text-slate-500">{filtered.length}</span> of{' '}
          <span className="tnum text-slate-500">{alerts.length}</span> alerts
        </span>
        <div className="flex items-center gap-1.5">
          <button className="border border-line px-2 py-1 text-2xs text-slate-500 hover:text-slate-300 hover:border-line-strong transition-colors">
            Previous
          </button>
          <button className="border border-line px-2 py-1 text-2xs text-slate-500 hover:text-slate-300 hover:border-line-strong transition-colors">
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
