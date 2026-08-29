export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
export type AlertStatus = 'Active' | 'Investigating' | 'Contained' | 'Resolved';
export type ResponseAction = 'Block IP' | 'Disable User' | 'Notify Admin' | 'Quarantine';

export interface Alert {
  id: string;
  timestamp: string;
  sourceIp: string;
  alertType: string;
  severity: Severity;
  status: AlertStatus;
  action: ResponseAction | null;
  mitre: string[];
  country: string;
  destinationIp: string;
  mitreId: string;
}

export interface AttackingIp {
  ip: string;
  count: number;
  country: string;
  topSeverity: Severity;
  flag: string;
}

export interface MitreTag {
  id: string;
  name: string;
  count: number;
  tactic: string;
}

export const severityMeta: Record<
  Severity,
  { text: string; dot: string; hex: string }
> = {
  Critical: { text: 'text-sev-critical', dot: 'bg-sev-critical', hex: '#c2675a' },
  High: { text: 'text-sev-high', dot: 'bg-sev-high', hex: '#c79a5c' },
  Medium: { text: 'text-sev-medium', dot: 'bg-sev-medium', hex: '#b5a44e' },
  Low: { text: 'text-sev-low', dot: 'bg-sev-low', hex: '#5a9472' },
};

export const statusMeta: Record<
  AlertStatus,
  { text: string; dot: string }
> = {
  Active: { text: 'text-sev-critical', dot: 'bg-sev-critical' },
  Investigating: { text: 'text-accent-300', dot: 'bg-accent-400' },
  Contained: { text: 'text-sev-high', dot: 'bg-sev-high' },
  Resolved: { text: 'text-slate-400', dot: 'bg-slate-500' },
};

const alertTypes = [
  'Brute Force',
  'Port Scan',
  'SQL Injection',
  'Phishing',
  'XSS Attempt',
  'DDoS',
  'Credential Stuffing',
  'Ransomware Activity',
  'Privilege Escalation',
  'Command Injection',
];

const countries = [
  { name: 'Russia', code: 'RU' },
  { name: 'China', code: 'CN' },
  { name: 'North Korea', code: 'KP' },
  { name: 'Iran', code: 'IR' },
  { name: 'Brazil', code: 'BR' },
  { name: 'Netherlands', code: 'NL' },
  { name: 'United States', code: 'US' },
  { name: 'Germany', code: 'DE' },
  { name: 'India', code: 'IN' },
  { name: 'Vietnam', code: 'VN' },
];

const mitreMap: Record<string, { id: string; tactic: string }> = {
  'Brute Force': { id: 'T1110', tactic: 'Credential Access' },
  'Port Scan': { id: 'T1046', tactic: 'Discovery' },
  'SQL Injection': { id: 'T1190', tactic: 'Initial Access' },
  Phishing: { id: 'T1566', tactic: 'Initial Access' },
  'XSS Attempt': { id: 'T1059.007', tactic: 'Execution' },
  DDoS: { id: 'T1498', tactic: 'Impact' },
  'Credential Stuffing': { id: 'T1110.004', tactic: 'Credential Access' },
  'Ransomware Activity': { id: 'T1486', tactic: 'Impact' },
  'Privilege Escalation': { id: 'T1068', tactic: 'Privilege Escalation' },
  'Command Injection': { id: 'T1059.004', tactic: 'Execution' },
};

function randIp(): string {
  const octet = () => Math.floor(Math.random() * 254) + 1;
  return `${octet()}.${octet()}.${octet()}.${octet()}`;
}

// Deterministic-ish seeded data so the demo always looks coherent
const severityWeights: Severity[] = [
  'Critical',
  'Critical',
  'High',
  'High',
  'High',
  'Medium',
  'Medium',
  'Medium',
  'Low',
  'Low',
];

function pick<T>(arr: T[], i: number): T {
  return arr[i % arr.length];
}

function buildAlerts(count: number): Alert[] {
  const alerts: Alert[] = [];
  const now = new Date('2026-08-29T09:42:00');
  const statuses: AlertStatus[] = ['Active', 'Investigating', 'Contained', 'Resolved'];
  const statusWeights = [0.35, 0.25, 0.2, 0.2];
  const actions: (ResponseAction | null)[] = ['Block IP', 'Disable User', 'Notify Admin', 'Quarantine', null];

  // Predefined realistic source IPs so "top attacking IPs" stays coherent
  const sourceIps = [
    '45.146.203.14',
    '185.220.101.47',
    '194.165.16.77',
    '103.97.176.12',
    '212.193.30.218',
    '89.248.163.5',
    '141.98.11.84',
    '61.177.172.42',
    '218.92.0.143',
    '167.94.138.50',
  ];

  for (let i = 0; i < count; i++) {
    const typeIdx = i % alertTypes.length;
    const alertType = alertTypes[typeIdx];
    const mitre = mitreMap[alertType];
    const sevIdx = Math.floor((i * 7) % severityWeights.length);
    const severity = severityWeights[sevIdx];
    const sourceIp = sourceIps[i % sourceIps.length];
    const country = pick(countries, (i * 3) % countries.length);

    const minutesAgo = i * 17 + Math.floor(Math.random() * 9);
    const ts = new Date(now.getTime() - minutesAgo * 60000);

    // weighted status
    const r = Math.random();
    let acc = 0;
    let status: AlertStatus = 'Active';
    for (let s = 0; s < statuses.length; s++) {
      acc += statusWeights[s];
      if (r < acc) {
        status = statuses[s];
        break;
      }
    }

    const action =
      severity === 'Critical' || severity === 'High'
        ? actions[i % 4]
        : Math.random() > 0.4
          ? null
          : actions[2];

    alerts.push({
      id: `ALR-${(2048 + i).toString()}`,
      timestamp: ts.toISOString(),
      sourceIp,
      alertType,
      severity,
      status,
      action,
      mitre: [mitre.id],
      country: country.name,
      destinationIp: randIp(),
      mitreId: mitre.id,
    });
  }
  return alerts.sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );
}

export const alerts: Alert[] = buildAlerts(24);

export function buildAttackingIps(list: Alert[]): AttackingIp[] {
  const map = new Map<string, AttackingIp>();
  for (const a of list) {
    const existing = map.get(a.sourceIp);
    if (existing) {
      existing.count++;
      const rank: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };
      if (rank[a.severity] > rank[existing.topSeverity]) {
        existing.topSeverity = a.severity;
      }
    } else {
      const c = countries.find((c) => c.name === a.country) ?? countries[0];
      map.set(a.sourceIp, {
        ip: a.sourceIp,
        count: 1,
        country: c.name,
        topSeverity: a.severity,
        flag: c.code,
      });
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}

export const attackingIps: AttackingIp[] = buildAttackingIps(alerts);

export function buildMitreTags(list: Alert[]): MitreTag[] {
  const map = new Map<string, MitreTag>();
  for (const a of list) {
    const m = mitreMap[a.alertType];
    if (!m) continue;
    const existing = map.get(m.id);
    if (existing) {
      existing.count++;
    } else {
      map.set(m.id, {
        id: m.id,
        name: a.alertType,
        count: 1,
        tactic: m.tactic,
      });
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}

export const mitreTags: MitreTag[] = buildMitreTags(alerts);

export const timelineData = [
  { day: 'Aug 23', critical: 8, high: 19, medium: 31, low: 22 },
  { day: 'Aug 24', critical: 12, high: 24, medium: 28, low: 19 },
  { day: 'Aug 25', critical: 6, high: 16, medium: 35, low: 27 },
  { day: 'Aug 26', critical: 15, high: 28, medium: 33, low: 21 },
  { day: 'Aug 27', critical: 9, high: 22, medium: 29, low: 24 },
  { day: 'Aug 28', critical: 18, high: 31, medium: 38, low: 26 },
  { day: 'Aug 29', critical: 11, high: 20, medium: 24, low: 17 },
];

export const severityCounts = {
  Critical: alerts.filter((a) => a.severity === 'Critical').length + 47,
  High: alerts.filter((a) => a.severity === 'High').length + 118,
  Medium: alerts.filter((a) => a.severity === 'Medium').length + 213,
  Low: alerts.filter((a) => a.severity === 'Low').length + 156,
};

export const stats = [
  {
    id: 'total',
    label: 'Total Alerts',
    value: '1,247',
    sub: 'Last 7 days',
    delta: '+8.2%',
    trend: 'up' as const,
    deltaNegative: true,
    icon: 'Bell',
  },
  {
    id: 'critical',
    label: 'Critical Alerts',
    value: '79',
    sub: 'Require immediate action',
    delta: '+12.4%',
    trend: 'up' as const,
    deltaNegative: true,
    icon: 'AlertOctagon',
  },
  {
    id: 'incidents',
    label: 'Active Incidents',
    value: '23',
    sub: '4 escalated today',
    delta: '+3',
    trend: 'up' as const,
    deltaNegative: true,
    icon: 'Crosshair',
  },
  {
    id: 'response',
    label: 'Avg Response Time',
    value: '4m 12s',
    sub: 'SOAR automated responses',
    delta: '-18.7%',
    trend: 'down' as const,
    deltaNegative: false,
    icon: 'Timer',
  },
];
