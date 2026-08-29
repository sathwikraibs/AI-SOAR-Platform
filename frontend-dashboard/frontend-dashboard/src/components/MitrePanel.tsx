import { ExternalLink } from 'lucide-react';
import { mitreTags } from '@/data/mockData';

// Muted tactic colors — just text + border tints, no bright fills
const tacticColors: Record<string, string> = {
  'Credential Access': 'text-sev-high border-sev-high/30',
  Discovery: 'text-accent-300 border-accent-600/30',
  'Initial Access': 'text-sev-critical border-sev-critical/30',
  Execution: 'text-slate-400 border-line-strong',
  Impact: 'text-sev-medium border-sev-medium/30',
  'Privilege Escalation': 'text-slate-400 border-line-strong',
};

export function MitrePanel() {
  return (
    <div className="border border-line bg-base-900 p-3.5">
      <div className="flex items-center justify-between mb-2.5">
        <div>
          <h3 className="text-xs font-semibold text-slate-200">MITRE ATT&amp;CK</h3>
          <p className="text-2xs text-slate-600 mt-0.5">Tactics in recent alerts</p>
        </div>
        <button className="text-2xs text-accent-300 hover:text-accent-300/80 flex items-center gap-1">
          Framework
          <ExternalLink className="h-2.5 w-2.5" />
        </button>
      </div>

      <div className="space-y-1.5">
        {mitreTags.map((tag) => {
          const colorClass =
            tacticColors[tag.tactic] ?? 'text-slate-400 border-line-strong';
          return (
            <div
              key={tag.id}
              className="flex items-center gap-2.5 border border-line bg-base-850/40 px-2.5 py-1.5 hover:border-line-strong transition-colors"
            >
              <span className="font-mono text-2xs font-semibold text-slate-500 w-[62px] shrink-0">
                {tag.id}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-2xs text-slate-300 truncate">{tag.name}</p>
                <p className="text-2xs text-slate-600 truncate">{tag.tactic}</p>
              </div>
              <span
                className={`tnum flex items-center border px-1.5 py-0.5 text-2xs font-semibold ${colorClass}`}
              >
                {tag.count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
