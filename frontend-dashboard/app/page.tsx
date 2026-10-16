'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps'
import world from 'world-atlas/countries-110m.json'
import {
  Activity, AlertTriangle, ArrowUpRight, Bell, BookOpen, Bot, Box,
  ChevronDown, ChevronLeft, ChevronRight, CircleDot, Clock3, Command, Crosshair,
  Database, FileClock, FileText, Globe2, Inbox, KeyRound, LayoutDashboard, LockKeyhole,
  Menu, Network, Play, Plus, Radio, Search, Server, Settings, Shield, ShieldAlert,
  SlidersHorizontal, Terminal, UserRound, Users, X, Zap,
} from 'lucide-react'

const COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#64748b', success: '#22c55e', pending: '#a855f7' }

// Backend base URL. The FastAPI backend (backend/main.py) runs on
// localhost:8000 by default with CORS already open for the dashboard's
// dev origin. Override with NEXT_PUBLIC_API_BASE if it runs elsewhere.
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000'

async function fetchJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`)
  if (!res.ok) throw new Error(`${path} -> ${res.status}`)
  return res.json() as Promise<T>
}

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
type Alert = { id:string; rawId:number; severity:Severity; time:string; ts:number; detection:string; source:string; asset:string; technique:string; score:number; status:string }

// Every stage of the pipeline (detection-agent's watcher*.py) stamps
// events with datetime.now(timezone.utc), but by the time a timestamp has
// gone through the DB and back out of FastAPI it lands here as a naive
// ISO string with no "Z"/offset (e.g. "2026-09-19T13:36:12.740000") --
// confirmed against the actual sqlite rows. `new Date(...)` treats an
// offset-less ISO string as *local* time, not UTC, which silently shifts
// every displayed time by the browser's UTC offset (+5:30 in India, so a
// 13:36 UTC event would otherwise show as 13:36 instead of 19:06). Force
// UTC interpretation by appending "Z" whenever the string has no zone of
// its own, everywhere a backend timestamp is turned into a clock time.
//
// Display timezone preference (Settings tab): a plain module-level
// variable, not React state, because toLocalTime()/toLocalDateTime() are
// called from a dozen+ components (Alerts, Incidents, Audit, Assets, SSH
// Sessions, Response Center, Reports...) that would otherwise all need
// this threaded through as a prop. Switching tabs already fully remounts
// the content pane (see Page()'s `key={active}`), so changing this in
// Settings and then navigating elsewhere is enough for every timestamp to
// pick up the new preference -- no extra plumbing needed.
const TIMEZONE_PREF_KEY = 'soar-timezone-pref'
let _displayTimezone: 'local' | 'utc' = 'local'
function getDisplayTimezone(): 'local' | 'utc' { return _displayTimezone }
function setDisplayTimezone(tz: 'local' | 'utc'): void {
  _displayTimezone = tz
  try { localStorage.setItem(TIMEZONE_PREF_KEY, tz) } catch { /* private-mode/storage-disabled — pref just won't persist across reloads */ }
}

// Which tab Page() opens on next time the dashboard loads (Settings tab
// lets an analyst pick Overview/Alerts/Incidents). Same pattern as the
// timezone pref: written to localStorage on change, read once on mount.
const DEFAULT_TAB_KEY = 'soar-default-tab'
function setDefaultLandingTab(tab: string): void {
  try { localStorage.setItem(DEFAULT_TAB_KEY, tab) } catch { /* ignore */ }
}

// Currently-logged-in admin (Admin Panel tab). Same module-level +
// localStorage pattern as the timezone/landing-tab prefs above, so the
// sidebar's bottom-left label (and the report-download `downloaded_by`
// param) can read it from anywhere without prop-threading. Page() also
// keeps this mirrored in React state (see its own currentAdmin state) so
// the sidebar label actually re-renders when it changes -- this
// module-level copy is what non-React call sites (report download links)
// read from.
type AdminInfo = { id:number; name:string; company_id:string; role:string|null; session_id:number|null }
const ADMIN_STORAGE_KEY = 'soar-current-admin'
let _currentAdmin: AdminInfo | null = null
function getCurrentAdminName(): string | null { return _currentAdmin?.name || null }
function persistCurrentAdmin(admin: AdminInfo | null): void {
  _currentAdmin = admin
  try {
    if (admin) localStorage.setItem(ADMIN_STORAGE_KEY, JSON.stringify(admin))
    else localStorage.removeItem(ADMIN_STORAGE_KEY)
  } catch { /* ignore */ }
}
function loadCurrentAdmin(): AdminInfo | null {
  try {
    const raw = localStorage.getItem(ADMIN_STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    _currentAdmin = parsed
    return parsed
  } catch { return null }
}
// Python's isoformat() (used by both FastAPI's raw DB timestamps and
// integration_health.py's failure log) writes microsecond precision --
// 6 fractional digits, e.g. "13:36:12.740000" -- but the ECMA-262 Date
// Time String Format `new Date()` officially parses only supports
// milliseconds (3 digits). Browsers are lenient about the extra digits in
// practice, but it's not guaranteed by spec, so trim to milliseconds
// explicitly rather than relying on that leniency.
function normalizeIsoFraction(iso: string): string {
  return iso.replace(/(\.\d{3})\d+/, '$1')
}
// The backend writes timestamps with Python's isoformat(), which for a
// naive UTC datetime (what every real timestamp in this app is) has NO
// "Z" or offset suffix at all -- e.g. "2026-09-25T19:12:46.740000", not
// "...Z". `new Date(...)` on a string like that does NOT treat it as UTC;
// per spec it's parsed as the BROWSER'S LOCAL time zone. So on a machine
// running IST (UTC+5:30), every real alert's parsed instant comes out
// 5.5 hours EARLIER than the timestamp actually means -- i.e. every alert
// silently looks 5.5 hours older than it really is. That's normally
// invisible in a display string (a wrong instant still prints *some*
// plausible-looking time), but it breaks anything that measures "how long
// ago" -- exactly what the Overview page's range filter does. An alert
// that's genuinely 18-19 hours old gets miscounted as ~24 hours old and
// silently drops out of "Last 24 Hours", even though the sidebar's
// unconditional total (no range filter) still shows it. This one helper
// is the fix: always append "Z" when the string has no zone of its own,
// so every caller -- display or math -- agrees on the same, correct UTC
// instant. (See parseApiTimestamp's callers below for the math side.)
function parseApiTimestamp(iso: string | null | undefined): number {
  if (!iso) return NaN
  const normalized = normalizeIsoFraction(iso)
  const hasZone = /Z$|[+-]\d{2}:?\d{2}$/.test(normalized)
  return new Date(hasZone ? normalized : `${normalized}Z`).getTime()
}
function toLocalTime(iso: string | null | undefined): string {
  const t = parseApiTimestamp(iso)
  if (isNaN(t)) return '—'
  const d = new Date(t)
  if (_displayTimezone === 'utc') return `${d.toLocaleTimeString([], { hour12:false, timeZone:'UTC' })} UTC`
  return d.toLocaleTimeString([], { hour12:false })
}

// Same UTC-fix as toLocalTime, but keeps the date too. A time-only column
// (05:40:25) reads as "out of order" the moment a log spans more than one
// day -- e.g. an event at 05:40 today looks older than one at 14:13
// yesterday even though it's actually the newer row. Audit's log is
// exactly the place that happens (system events one afternoon, an
// analyst's approve/reject the next morning), so it gets date+time.
function toLocalDateTime(iso: string | null | undefined): string {
  const t = parseApiTimestamp(iso)
  if (isNaN(t)) return '—'
  const d = new Date(t)
  if (_displayTimezone === 'utc') return `${d.toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false, timeZone:'UTC' })} UTC`
  return d.toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false })
}

// Shape returned by GET /alerts and GET /alerts/{id} on the real backend
// (database/models.py's Alert row, serialized as-is by FastAPI).
type ApiAlert = { id:number; source:string; description:string; severity:string; ip:string|null; hash?:string|null; timestamp:string; ip_reputation?:string|null; hash_reputation?:string|null; threat_score?:number|null; mitre_technique?:string|null; risk_score?:number|null; response_action?:string|null; response_status?:string|null }
function mapAlert(a: ApiAlert): Alert {
  return {
    id: `ALT-${a.id}`,
    rawId: a.id,
    severity: (a.severity as Severity) || 'Low',
    time: toLocalTime(a.timestamp),
    ts: parseApiTimestamp(a.timestamp),
    detection: a.description,
    source: a.ip || a.source,
    asset: a.source,
    technique: a.mitre_technique || '—',
    score: a.risk_score ?? 0,
    status: a.response_status || 'pending_approval',
  }
}

// Fixed reference point for the fallback data below -- deliberately NOT
// Date.now(). This array is a module-level constant, so it's only built
// ONCE per JS environment: once when Node evaluates this module to render
// the page on the server, and once again, separately, when the browser
// parses its own copy of the bundle to hydrate. Date.now() returns a
// DIFFERENT value in each of those two evaluations (they don't happen at
// the same instant), which used to bake two different sets of `ts` values
// into this same array -- server and client disagreed on the chart's
// bucket time labels ("23:29" vs "23:02"), and React flagged it as a real
// hydration mismatch. Date.parse() of a fixed literal string, unlike
// Date.now(), always returns the exact same number no matter when or
// where it runs, so every environment computes the identical array.
const MOCK_ANCHOR_MS = Date.parse('2026-01-15T09:42:18Z')
// Static fallback shown only if the backend at API_BASE can't be reached
// (e.g. it isn't running yet) so the dashboard doesn't just go blank.
const mockAlerts: Alert[] = [
  { id:'ALT-20481', rawId:20481, severity:'Critical', time:'09:42:18', ts:MOCK_ANCHOR_MS-2*3600_000, detection:'Credential stuffing detected across multiple accounts', source:'185.220.101.42', asset:'auth-gateway-01', technique:'T1110.004', score:98, status:'pending_approval' },
  { id:'ALT-20480', rawId:20480, severity:'High', time:'09:41:52', ts:MOCK_ANCHOR_MS-3*3600_000, detection:'Suspicious executable uploaded to target-app', source:'45.148.10.77', asset:'target-app-prod', technique:'T1204.002', score:87, status:'auto_resolved' },
  { id:'ALT-20479', rawId:20479, severity:'High', time:'09:39:07', ts:MOCK_ANCHOR_MS-5*3600_000, detection:'Path traversal attempt blocked by WAF', source:'103.27.186.14', asset:'edge-proxy-02', technique:'T1190', score:82, status:'approved_and_executed' },
  { id:'ALT-20478', rawId:20478, severity:'Medium', time:'09:36:44', ts:MOCK_ANCHOR_MS-8*3600_000, detection:'Repeated failed login attempts from source IP', source:'91.240.118.172', asset:'vpn-gateway', technique:'T1110', score:64, status:'auto_resolved' },
  { id:'ALT-20477', rawId:20477, severity:'Low', time:'09:31:22', ts:MOCK_ANCHOR_MS-11*3600_000, detection:'New user agent observed on admin endpoint', source:'172.16.4.22', asset:'admin-console', technique:'T1078', score:31, status:'rejected' },
]

// GET /incidents shape (backend groups alerts by source IP — see
// backend/main.py's _summarize_incident()). No "status" field exists on
// the real backend; any_pending_approval is the closest equivalent.
type ApiIncident = { incident_id:number; ip:string; alert_count:number; alert_ids:number[]; max_severity:string; mitre_techniques:string[]; any_pending_approval:boolean; first_seen:string; last_seen:string }

// GET /reports shape.
type ApiReport = { filename:string; generated_at:string; download_url:string }
// backend's GET /reports derives generated_at straight from the filename
// (report_<YYYYMMDD>_<HHMMSS>.pdf, stamped in UTC by report-generator's
// datetime.now(timezone.utc)) and never parses it into a real date -- so
// without this it rendered as the raw digits "20260924_140500" instead of
// a readable, correctly-local-converted time.
function formatReportTimestamp(raw: string): string {
  const m = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$/.exec(raw)
  if (!m) return raw
  const [, y, mo, d, h, mi, s] = m
  // Route through toLocalDateTime instead of formatting inline, so this
  // also honors the Settings "Timestamp display" (Local Time / UTC)
  // preference like every other timestamp in the app -- it was previously
  // hardcoded to local time only, which would've been the one inconsistent
  // clock left after that setting was added.
  const formatted = toLocalDateTime(`${y}-${mo}-${d}T${h}:${mi}:${s}Z`)
  return formatted === '—' ? raw : formatted
}

function ApiNotice({ show }: { show:boolean }) { return show ? <p className="muted" style={{margin:'0 0 16px'}}>Can't reach the backend at {API_BASE} right now — showing example data.</p> : null }
const nav = [
  ['COMMAND','Overview',LayoutDashboard],['MONITOR','Alerts',AlertTriangle],['MONITOR','Incidents',ShieldAlert],['MONITOR','Investigations',Crosshair],['AUTOMATE','Playbooks',Play],['AUTOMATE','Runbook',BookOpen],['INTELLIGENCE','Threat Intelligence',Database],['INTELLIGENCE','Global Threat Map',Globe2],['OPERATIONS','Assets',Server],['OPERATIONS','Response Center',Zap],['OPERATIONS','SSH / Sessions',Terminal],['SYSTEM','Audit',FileClock],['SYSTEM','Reports',FileText],['SYSTEM','24-Hour Report',Clock3],['SYSTEM','Detection Rules',SlidersHorizontal],['SYSTEM','Integrations',Network],['SYSTEM','Admin Panel',LockKeyhole],['SYSTEM','Settings',Settings],
]

function SeverityBadge({ severity }: { severity: string }) { const c = COLORS[severity.toLowerCase() as keyof typeof COLORS] || COLORS.info; return <span className="badge" style={{color:c, borderColor:`${c}55`, background:`${c}12`}}><span className="severity-dot" style={{background:c}} />{severity}</span> }
function StatusBadge({ status }: { status: string }) { const labels:Record<string,string>={auto_resolved:'AUTO-RESOLVED',pending_approval:'PENDING APPROVAL',approved_and_executed:'EXECUTED',rejected:'REJECTED'}; const c=status==='auto_resolved'?COLORS.success:status==='pending_approval'?COLORS.pending:status==='rejected'?COLORS.critical:'#2dd4bf'; return <span className="status" style={{color:c, borderColor:`${c}55`, background:`${c}12`}}><span className="status-dot" style={{background:c}} />{labels[status]||status}</span> }
function Panel({ title, action, onAction, children, className='' }: {title:string; action?:string; onAction?:()=>void; children:React.ReactNode; className?:string}) { return <section className={`panel ${className}`}><div className="panel-head"><h2>{title}</h2>{action && <button className="text-button" onClick={onAction}>{action}<ArrowUpRight size={13}/></button>}</div>{children}</section> }
function Sparkline({ color }: {color:string}) { return <svg className="spark" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true"><polyline points="0,22 12,19 23,21 34,13 46,16 57,8 68,12 80,7 91,10 100,3" fill="none" stroke={color} strokeWidth="1.8" /></svg> }
function Kpi({ label, value, change, color }: {label:string;value:string;change:string;color:string}) { return <div className="kpi"><div className="kpi-top"><span>{label}</span><ArrowUpRight size={14} style={{color}}/></div><strong style={{color}}>{value}</strong><div className="kpi-foot"><span className="trend">{change}</span><span>from backend</span></div><Sparkline color={color}/></div> }
// Buckets real (severity, epoch-ms) points into `numBuckets` even time
// slices spanning the data's own min..max timestamp, counted per severity
// tier and returned as cumulative running totals (keeps the same "rising
// trend" shape the old hardcoded chart had, but driven by real numbers).
function bucketizeBySeverity(points: {ts:number; severity:string}[], numBuckets=6) {
  if (points.length===0) {
    return { labels: Array(numBuckets).fill('--:--'), critical:Array(numBuckets).fill(0), high:Array(numBuckets).fill(0), medium:Array(numBuckets).fill(0) }
  }
  const times = points.map(p=>p.ts)
  const min = Math.min(...times), max = Math.max(...times)
  const span = Math.max(max-min, 60_000) // at least a minute, so a single-instant burst doesn't divide by zero
  const bucketSize = span/numBuckets
  const critical=Array(numBuckets).fill(0), high=Array(numBuckets).fill(0), medium=Array(numBuckets).fill(0)
  const labels:string[]=[]
  for(let i=0;i<numBuckets;i++){
    // hour12:false matters here, not just style: with it left as the locale
    // default, Node's server-side render and the browser's client render
    // can format AM/PM differently (e.g. "10:45 pm" vs "10:45 PM"), and
    // React treats that text mismatch as a hydration error. 24-hour time
    // has no AM/PM string to disagree on -- same reason toLocalTime() above
    // always passes hour12:false too.
    labels.push(new Date(min+i*bucketSize).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',hour12:false}))
  }
  points.forEach(p=>{
    let idx = Math.floor((p.ts-min)/bucketSize)
    if(idx>=numBuckets) idx=numBuckets-1
    if(idx<0) idx=0
    if(p.severity==='Critical') critical[idx]++
    else if(p.severity==='High') high[idx]++
    else medium[idx]++ // Medium and Low both roll into the yellow line -- the chart only ever plotted 3 lines
  })
  const cum=(arr:number[])=>{ let s=0; return arr.map(v=>s+=v) }
  return { labels, critical:cum(critical), high:cum(high), medium:cum(medium) }
}
function ThreatChart({ labels, critical, high, medium }: { labels:string[]; critical:number[]; high:number[]; medium:number[] }) {
  const maxVal = Math.max(1, ...critical, ...high, ...medium)
  const n = Math.max(labels.length,1)
  const x = (i:number)=> n>1 ? i*(700/(n-1)) : 350
  const y = (v:number)=> 185 - (v/maxVal)*160
  const pathFor=(arr:number[])=>arr.map((v,i)=>`${x(i)},${y(v)}`).join(' ')
  const areaFor=(arr:number[])=>`M0 185 ${arr.map((v,i)=>`L ${x(i)} ${y(v)}`).join(' ')} L700 190 L0 190 Z`
  return <div className="chart-wrap"><div className="chart-y"><span>{maxVal}</span><span>{Math.round(maxVal*0.75)}</span><span>{Math.round(maxVal*0.5)}</span><span>{Math.round(maxVal*0.25)}</span><span>0</span></div><div className="chart"><div className="grid-lines" /> <svg viewBox="0 0 700 190" preserveAspectRatio="none"><defs><linearGradient id="area" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#ef4444" stopOpacity=".26"/><stop offset="1" stopColor="#ef4444" stopOpacity="0"/></linearGradient></defs><path d={areaFor(critical)} fill="url(#area)"/><polyline points={pathFor(critical)} fill="none" stroke="#ef4444" strokeWidth="2"/><polyline points={pathFor(high)} fill="none" stroke="#f97316" strokeWidth="2"/><polyline points={pathFor(medium)} fill="none" stroke="#eab308" strokeWidth="1.5"/></svg><div className="chart-x">{labels.map((l,i)=><span key={i}>{l}</span>)}</div></div></div>
}
const RANGE_OPTIONS: {label:string; ms:number}[] = [
  { label:'Last 24 Hours', ms:24*3600_000 },
  { label:'Last 7 Days', ms:7*24*3600_000 },
  { label:'Last 30 Days', ms:30*24*3600_000 },
  { label:'All Time', ms:Infinity },
]
// Same open/close-on-outside-click pattern as FilterMenu, but a single-select
// list of time ranges (closes itself the moment one is picked) instead of a
// multi-select checkbox list.
function RangeMenu({ value, onChange }: {value:string; onChange:(v:string)=>void}) {
  const [open,setOpen]=useState(false)
  return <div style={{position:'relative'}}>
    <button className="outline-btn" onClick={()=>setOpen(o=>!o)}><Clock3 size={14}/> {value} <ChevronDown size={13}/></button>
    {open && <>
      <button aria-label="Close menu" onClick={()=>setOpen(false)} style={{position:'fixed',inset:0,background:'transparent',border:0,cursor:'default',zIndex:15}}/>
      <div style={{position:'absolute',top:'calc(100% + 6px)',right:0,zIndex:20,minWidth:170,background:'var(--surface)',border:'1px solid var(--border)',borderRadius:4,padding:4,boxShadow:'0 8px 24px rgba(0,0,0,.35)'}} onClick={e=>e.stopPropagation()}>
        {RANGE_OPTIONS.map(o=><button key={o.label} className="text-button" style={{display:'block',width:'100%',textAlign:'left',padding:'7px 9px'}} onClick={()=>{ onChange(o.label); setOpen(false) }}>{o.label}</button>)}
      </div>
    </>}
  </div>
}
const inputStyle:React.CSSProperties={background:'#0d1318',border:'1px solid var(--border)',padding:8,color:'var(--text)',outline:0}
// Manual incident reporting goes through the exact same POST /alerts
// pipeline every automated detection uses (AI classifier -> threat-intel
// enrichment -> risk scoring -> response playbook) -- not a separate,
// untested code path -- so it comes out the other side as a real alert
// that Incidents' IP-correlation and Overview's KPIs both already handle.
function CreateIncidentModal({ onClose, onCreated }: {onClose:()=>void; onCreated:()=>void}) {
  const [ip,setIp]=useState('')
  const [source,setSource]=useState('Analyst')
  const [description,setDescription]=useState('')
  const [submitting,setSubmitting]=useState(false)
  const [err,setErr]=useState<string|null>(null)
  const submit=async()=>{
    if(!description.trim()){ setErr('Description is required.'); return }
    setSubmitting(true); setErr(null)
    try{
      await api.createAlert({ source: source.trim()||'Analyst', description: description.trim(), ip: ip.trim()||null, timestamp: new Date().toISOString() })
      onCreated()
    }catch(e){ setErr(e instanceof Error ? e.message : 'Failed to create incident.') }
    finally{ setSubmitting(false) }
  }
  return <><button className="drawer-backdrop" aria-label="Close" onClick={onClose}/><aside className="drawer" style={{width:'min(420px,100vw)'}}>
    <div className="drawer-head"><div><div className="eyebrow">MANUAL REPORT</div><h2 style={{fontSize:16}}>Create incident</h2></div><button className="icon-btn" onClick={onClose}><X size={18}/></button></div>
    <div className="drawer-summary" style={{display:'flex',flexDirection:'column',gap:12}}>
      <label style={{display:'flex',flexDirection:'column',gap:5,color:'var(--dim)',fontSize:10}}>Source IP (optional)<input value={ip} onChange={e=>setIp(e.target.value)} placeholder="e.g. 185.220.101.42" style={inputStyle}/></label>
      <label style={{display:'flex',flexDirection:'column',gap:5,color:'var(--dim)',fontSize:10}}>Reported by<input value={source} onChange={e=>setSource(e.target.value)} placeholder="Analyst" style={inputStyle}/></label>
      <label style={{display:'flex',flexDirection:'column',gap:5,color:'var(--dim)',fontSize:10}}>Description<input value={description} onChange={e=>setDescription(e.target.value)} placeholder="What happened?" style={inputStyle}/></label>
      {err && <span style={{color:COLORS.critical,fontSize:11}}>{err}</span>}
      <button className="primary-btn" onClick={submit} disabled={submitting} style={{justifyContent:'center'}}>{submitting?'Submitting…':'Submit incident'}</button>
      <span className="muted" style={{fontSize:10}}>Runs through the same AI classification, enrichment and response pipeline as an automatically-detected alert.</span>
    </div>
  </aside></>
}
function Overview({ onSelect, refreshKey, onNavigate, bumpRefresh }: {onSelect:(a:Alert)=>void; refreshKey?:number; onNavigate:(tab:string)=>void; bumpRefresh:()=>void}) {
  const [alerts,setAlerts]=useState<Alert[]|null>(null)
  const [incidents,setIncidents]=useState<ApiIncident[]|null>(null)
  const [apiError,setApiError]=useState(false)
  const [range,setRange]=useState('Last 24 Hours')
  const [chartTab,setChartTab]=useState<'Alerts'|'Incidents'|'Actions'>('Alerts')
  const [showCreate,setShowCreate]=useState(false)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiAlert[]>('/alerts').then(data=>{ if(!cancelled) setAlerts(data.map(mapAlert)) }).catch(()=>{ if(!cancelled){ setApiError(true); setAlerts(mockAlerts) } })
    fetchJSON<ApiIncident[]>('/incidents').then(data=>{ if(!cancelled) setIncidents(data) }).catch(()=>{ if(!cancelled) setIncidents(null) })
    return ()=>{ cancelled=true }
  },[refreshKey])
  const rangeMs = RANGE_OPTIONS.find(o=>o.label===range)?.ms ?? Infinity
  const allAlerts = alerts ?? mockAlerts
  const list = useMemo(()=>allAlerts.filter(a=>Date.now()-a.ts<=rangeMs), [allAlerts, rangeMs])
  const incidentsInRange = useMemo(()=>(incidents ?? []).filter(i=>Date.now()-parseApiTimestamp(i.first_seen)<=rangeMs), [incidents, rangeMs])
  const criticalCount = list.filter(a=>a.severity==='Critical').length
  const highCount = list.filter(a=>a.severity==='High').length
  const resolvedCount = list.filter(a=>a.status==='auto_resolved'||a.status==='approved_and_executed').length
  const avgRisk = list.length ? (list.reduce((sum,a)=>sum+a.score,0)/list.length).toFixed(1) : '0.0'
  const bySeverity = (s:Severity)=>list.filter(a=>a.severity===s).length
  const byStatus = (s:string)=>list.filter(a=>a.status===s).length
  // "Top attack types" used to be 5 hardcoded (name, percentage) pairs that
  // never changed no matter what actually came in. Real version: group by
  // the human-readable half of the real MITRE technique string the backend
  // already computed (threat_intel.py's map_to_mitre(), e.g.
  // "T1110 - Brute Force" -> "Brute Force"), count real alerts per category,
  // and bar-width each relative to the biggest real category.
  const attackTypeCounts = useMemo(()=>{
    const counts: Record<string, number> = {}
    list.forEach(a=>{
      const name = a.technique && a.technique!=='—' ? (a.technique.split(' - ')[1] || a.technique) : 'Uncategorized'
      counts[name] = (counts[name]||0)+1
    })
    return Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,5)
  }, [list])
  const maxAttackCount = Math.max(1, ...attackTypeCounts.map(([,c])=>c))
  const attackTypeColors = [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low, COLORS.info]
  // "Alerts" plots every alert in range; "Incidents" plots the correlated
  // view instead; "Actions" narrows to alerts that have actually had a
  // response outcome (i.e. left "pending_approval") -- all three reuse the
  // exact same severity-colored legend/lines, just over a different, real
  // slice of the same underlying data.
  const chartData = useMemo(()=>{
    if(chartTab==='Incidents') return bucketizeBySeverity(incidentsInRange.map(i=>({ts:parseApiTimestamp(i.first_seen), severity:i.max_severity})))
    if(chartTab==='Actions') return bucketizeBySeverity(list.filter(a=>a.status!=='pending_approval').map(a=>({ts:a.ts, severity:a.severity})))
    return bucketizeBySeverity(list.map(a=>({ts:a.ts, severity:a.severity})))
  }, [chartTab, list, incidentsInRange])
  return <>
  <div className="page-title"><div><div className="eyebrow">{`COMMAND CENTER / ${range.toUpperCase()}`}</div><h1>Overview</h1></div><div className="title-actions"><RangeMenu value={range} onChange={setRange}/><button className="primary-btn" onClick={()=>setShowCreate(true)}><Plus size={15}/> Create incident</button></div></div>
  <ApiNotice show={apiError}/>
  <div className="kpi-grid"><Kpi label="Active incidents" value={incidents!=null?String(incidentsInRange.length).padStart(2,'0'):'—'} change="live" color={COLORS.critical}/><Kpi label="Critical alerts" value={String(criticalCount).padStart(2,'0')} change="live" color={COLORS.critical}/><Kpi label="High alerts" value={String(highCount).padStart(2,'0')} change="live" color={COLORS.high}/><Kpi label="Resolved" value={String(resolvedCount).padStart(2,'0')} change="live" color={COLORS.success}/><Kpi label="Avg risk score" value={avgRisk} change="live" color={COLORS.medium}/></div>
  <div className="overview-grid"><Panel title="Threat activity" action="View alerts" onAction={()=>onNavigate('Alerts')} className="activity-panel"><div className="legend"><span><i style={{background:COLORS.critical}}/>Critical</span><span><i style={{background:COLORS.high}}/>High</span><span><i style={{background:COLORS.medium}}/>Medium</span><span><i style={{background:COLORS.low}}/>Low</span><div className="segmented">{(['Alerts','Incidents','Actions'] as const).map(t=><button key={t} className={chartTab===t?'selected':''} onClick={()=>setChartTab(t)}>{t}</button>)}</div></div><ThreatChart {...chartData}/></Panel><Panel title="Current security posture"><div className="posture"><div className="donut"><div><strong>{list.length}</strong><span>tracked alerts</span></div></div><div className="posture-list"><div><span><i style={{background:COLORS.critical}}/>Critical</span><b>{String(bySeverity('Critical')).padStart(2,'0')}</b></div><div><span><i style={{background:COLORS.high}}/>High</span><b>{String(bySeverity('High')).padStart(2,'0')}</b></div><div><span><i style={{background:COLORS.medium}}/>Medium</span><b>{String(bySeverity('Medium')).padStart(2,'0')}</b></div><div><span><i style={{background:COLORS.low}}/>Low</span><b>{String(bySeverity('Low')).padStart(2,'0')}</b></div></div></div><div className="response-mini"><span>Response status</span>{(['pending_approval','auto_resolved','approved_and_executed','rejected'] as const).filter(s=>byStatus(s)>0).map(s=><span key={s} style={{display:'inline-flex',alignItems:'center',gap:5}}><StatusBadge status={s}/><b style={{fontSize:11}}>{byStatus(s)}</b></span>)}{list.length===0 && <span className="muted" style={{fontSize:11}}>No alerts in range</span>}</div></Panel></div>
  <div className="lower-grid"><Panel title="Top attack types"><div className="bars">{attackTypeCounts.length===0 ? <p className="muted" style={{padding:'8px 0'}}>No alerts in this time range.</p> : attackTypeCounts.map(([name,count],i)=><div className="bar-row" key={name}><span>{name}</span><div><i style={{width:`${Math.round(count/maxAttackCount*100)}%`,background:attackTypeColors[i%attackTypeColors.length]}}/></div><b>{count}</b></div>)}</div></Panel><Panel title="Response status"><div className="bars response-bars">{[['auto_resolved',COLORS.success],['pending_approval',COLORS.pending],['approved_and_executed','#2dd4bf'],['rejected',COLORS.critical]].map(([n,c])=>{const count=byStatus(n as string);const pct=list.length?Math.round(count/list.length*100):0;return <div className="bar-row" key={String(n)}><span>{String(n).replaceAll('_',' ')}</span><div><i style={{width:`${pct}%`,background:c as string}}/></div><b>{count}</b></div>})}</div></Panel></div>
  <Panel title="Live security activity" action="Open activity log" onAction={()=>onNavigate('Audit')}><div className="activity-feed">{list.slice(0,5).map((a,i)=><button className="feed-row" key={a.id} onClick={()=>onSelect(a)}><span className="feed-time">{a.time}</span><SeverityBadge severity={a.severity}/><span className="feed-type">ALERT</span><span className="feed-desc">{a.detection}</span><code>{a.source}</code><span className="feed-asset">{a.asset}</span><span className="feed-id">{a.id}</span><ChevronRight size={14}/></button>)}{list.length===0 && <p className="muted" style={{padding:'12px 0'}}>No alerts in this time range.</p>}</div></Panel>
  {showCreate && <CreateIncidentModal onClose={()=>setShowCreate(false)} onCreated={()=>{ setShowCreate(false); bumpRefresh() }}/>}
 </> }
// Generic toolbar dropdown: a button that opens a small panel below it.
// A full-screen invisible backdrop behind the panel closes it on outside
// click, without darkening the page (unlike .drawer-backdrop).
function FilterMenu({ label, icon, count, children }: { label:string; icon?:React.ReactNode; count?:number; children:React.ReactNode }) {
  const [open,setOpen]=useState(false)
  return <div style={{position:'relative'}}>
    <button className="outline-btn" onClick={()=>setOpen(o=>!o)}>{icon}{label} <ChevronDown size={13}/>{!!count && <span className="filter-count">{count}</span>}</button>
    {open && <>
      <button aria-label="Close menu" onClick={()=>setOpen(false)} style={{position:'fixed',inset:0,background:'transparent',border:0,cursor:'default',zIndex:15}}/>
      <div style={{position:'absolute',top:'calc(100% + 6px)',left:0,zIndex:20,minWidth:190,background:'var(--surface)',border:'1px solid var(--border)',borderRadius:4,padding:8,boxShadow:'0 8px 24px rgba(0,0,0,.35)'}} onClick={e=>e.stopPropagation()}>
        {children}
      </div>
    </>}
  </div>
}
function CheckboxRow({ checked, onChange, label }: { checked:boolean; onChange:()=>void; label:React.ReactNode }) {
  return <label style={{display:'flex',alignItems:'center',gap:8,padding:'5px 4px',fontSize:12,color:'var(--text)',cursor:'pointer'}}>
    <input type="checkbox" checked={checked} onChange={onChange}/>{label}
  </label>
}

const SEVERITY_OPTIONS: Severity[] = ['Critical','High','Medium','Low']
const STATUS_OPTIONS: {value:string;label:string}[] = [
  { value:'pending_approval', label:'Pending approval' },
  { value:'auto_resolved', label:'Auto-resolved' },
  { value:'approved_and_executed', label:'Executed' },
  { value:'rejected', label:'Rejected' },
]
const ALL_COLUMNS = [
  { key:'severity', label:'SEVERITY' },
  { key:'time', label:'TIME' },
  { key:'id', label:'ALERT ID' },
  { key:'detection', label:'DETECTION' },
  { key:'source', label:'SOURCE IP' },
  { key:'asset', label:'ASSET / SOURCE' },
  { key:'technique', label:'MITRE' },
  { key:'score', label:'RISK' },
  { key:'status', label:'STATUS' },
] as const
type ColumnKey = typeof ALL_COLUMNS[number]['key']

function DataTable({ onSelect, refreshKey }: {onSelect:(a:Alert)=>void; refreshKey?:number}) {
  const [query,setQuery]=useState('')
  const [alerts,setAlerts]=useState<Alert[]|null>(null)
  const [apiError,setApiError]=useState(false)
  const [severityFilter,setSeverityFilter]=useState<Set<Severity>>(new Set())
  const [statusFilter,setStatusFilter]=useState<Set<string>>(new Set())
  const [visibleCols,setVisibleCols]=useState<Set<ColumnKey>>(new Set(ALL_COLUMNS.map(c=>c.key)))
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiAlert[]>('/alerts').then(data=>{ if(!cancelled) setAlerts(data.map(mapAlert)) }).catch(()=>{ if(!cancelled){ setApiError(true); setAlerts(mockAlerts) } })
    return ()=>{ cancelled=true }
  },[refreshKey])
  const list = alerts ?? []
  const filtered=useMemo(()=>list.filter(a=>
    `${a.id} ${a.detection} ${a.source} ${a.asset}`.toLowerCase().includes(query.toLowerCase())
    && (severityFilter.size===0 || severityFilter.has(a.severity))
    && (statusFilter.size===0 || statusFilter.has(a.status))
  ),[list,query,severityFilter,statusFilter])
  const toggleSet = <T,>(setFn:React.Dispatch<React.SetStateAction<Set<T>>>, value:T) => setFn(prev=>{ const next=new Set(prev); next.has(value)?next.delete(value):next.add(value); return next })
  const toggleColumn = (key:ColumnKey) => setVisibleCols(prev=>{ const next=new Set(prev); if(next.has(key)){ if(next.size>1) next.delete(key) } else next.add(key); return next })
  const activeFilterCount = severityFilter.size + statusFilter.size
  const clearFilters = () => { setSeverityFilter(new Set()); setStatusFilter(new Set()) }
  const col = (key:ColumnKey) => visibleCols.has(key)
  return <><div className="page-title"><div><div className="eyebrow">MONITOR / ALERT QUEUE</div><h1>Alerts <span className="title-count">{filtered.length} of {list.length} total</span></h1></div><button className="outline-btn" onClick={clearFilters} disabled={activeFilterCount===0}><SlidersHorizontal size={14}/> Filters <span className="filter-count">{activeFilterCount}</span></button></div><ApiNotice show={apiError}/><div className="toolbar"><div className="search-box"><Search size={15}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search alerts, IPs, IDs..."/></div>
    <FilterMenu label="Severity" count={severityFilter.size}>
      {SEVERITY_OPTIONS.map(s=><CheckboxRow key={s} checked={severityFilter.has(s)} onChange={()=>toggleSet(setSeverityFilter,s)} label={<SeverityBadge severity={s}/>}/>)}
    </FilterMenu>
    <FilterMenu label="Status" count={statusFilter.size}>
      {STATUS_OPTIONS.map(s=><CheckboxRow key={s.value} checked={statusFilter.has(s.value)} onChange={()=>toggleSet(setStatusFilter,s.value)} label={s.label}/>)}
    </FilterMenu>
    <FilterMenu label="Columns">
      {ALL_COLUMNS.map(c=><CheckboxRow key={c.key} checked={visibleCols.has(c.key)} onChange={()=>toggleColumn(c.key)} label={c.label}/>)}
    </FilterMenu>
  </div><div className="table-panel"><table><thead><tr>{col('severity')&&<th>SEVERITY</th>}{col('time')&&<th>TIME</th>}{col('id')&&<th>ALERT ID</th>}{col('detection')&&<th>DETECTION</th>}{col('source')&&<th>SOURCE IP</th>}{col('asset')&&<th>ASSET / SOURCE</th>}{col('technique')&&<th>MITRE</th>}{col('score')&&<th>RISK</th>}{col('status')&&<th>STATUS</th>}</tr></thead><tbody>{filtered.map(a=><tr key={a.id} onClick={()=>onSelect(a)}>{col('severity')&&<td><SeverityBadge severity={a.severity}/></td>}{col('time')&&<td className="mono muted">{a.time}</td>}{col('id')&&<td className="mono linkish">{a.id}</td>}{col('detection')&&<td className="detection-cell">{a.detection}</td>}{col('source')&&<td className="mono">{a.source}</td>}{col('asset')&&<td>{a.asset}</td>}{col('technique')&&<td className="mono muted">{a.technique}</td>}{col('score')&&<td><b style={{color: a.score>90?COLORS.critical:a.score>70?COLORS.high:COLORS.medium}}>{a.score}</b></td>}{col('status')&&<td><StatusBadge status={a.status}/></td>}</tr>)}{filtered.length===0 && <tr><td colSpan={visibleCols.size} className="muted" style={{textAlign:'center',padding:'28px 0'}}>No alerts match the current filters.</td></tr>}</tbody></table></div></> }
function Drawer({ alert, close, onApprove, onReject, busy, error }: {alert:Alert;close:()=>void;onApprove:(a:Alert)=>void;onReject:(a:Alert)=>void;busy?:boolean;error?:string|null}) { const canAct = alert.status==='pending_approval'; return <><button className="drawer-backdrop" aria-label="Close drawer" onClick={close}/><aside className="drawer"><div className="drawer-head"><div><div className="eyebrow">ALERT INVESTIGATION</div><h2>{alert.id}</h2></div><button className="icon-btn" onClick={close}><X size={18}/></button></div><div className="drawer-summary"><SeverityBadge severity={alert.severity}/><h3>{alert.detection}</h3><div className="drawer-grid"><span>Risk score<strong>{alert.score}</strong></span><span>Source IP<strong className="mono">{alert.source}</strong></span><span>Asset<strong>{alert.asset}</strong></span><span>MITRE technique<strong className="mono">{alert.technique}</strong></span></div></div><div className="drawer-section"><div className="section-label">CURRENT STATUS</div><StatusBadge status={alert.status}/></div>{error && <p className="muted" style={{color:COLORS.critical}}>{error}</p>}<div className="drawer-actions">{canAct ? <><button className="reject-btn" disabled={busy} onClick={()=>onReject(alert)}>{busy?'Rejecting…':'Reject'}</button><button className="approve-btn" disabled={busy} onClick={()=>onApprove(alert)}>{busy?'Approving…':'Approve'}</button></> : <span className="muted">No pending approval on this alert.</span>}</div></aside></> }

const incidents=[['Critical','INC-0091','185.220.101.42','14','T1110.004, T1078','PENDING APPROVAL','09:42','09:47'],['High','INC-0090','45.148.10.77','6','T1204.002','APPROVED','09:18','09:41'],['High','INC-0089','103.27.186.14','9','T1190','EXECUTED','08:56','09:39'],['Medium','INC-0088','91.240.118.172','21','T1110','PENDING APPROVAL','08:22','09:36'],['Low','INC-0087','172.16.4.22','3','T1078','REVIEW','07:40','09:31']]
const iocs=[['185.220.101.42','IP','Malicious','AbuseIPDB','14'],['45.148.10.77','IP','Suspicious','VirusTotal','6'],['91.240.118.172','IP','Malicious','heuristic','21'],['a84f9c2d7e11b8a0','SHA256','Unknown','VirusTotal','2'],['103.27.186.14','IP','Suspicious','AbuseIPDB','9'],['d41d8cd98f00b204','MD5','Clean','VirusTotal','0'],['172.16.4.22','IP','Unknown','heuristic','3']]
const playbooks=[['Critical Malware / Ransomware Containment','Malware or ransomware behavior detected',['Isolate affected host (manual)','Kill malicious process (manual)','Quarantine file hash (manual)','Block related IPs (manual)','Page on-call analyst (auto)']],['Credential / Brute-Force Response','Repeated authentication failures',['Lock user account (manual)','Block source IP (manual)','Force password reset (manual)','Notify SOC (auto)']],['Reconnaissance / Scanning Response','Port scan or broad discovery',['Add IP to watchlist (auto)','Rate-limit traffic (auto)','Log for correlation (auto)']],['Data Exfiltration Containment','Unusual outbound data volume',['Isolate host (manual)','Block outbound IP (manual)','Snapshot for forensics (auto)','Page analyst (auto)']],['Web Application Attack Response','WAF or application exploit detected',['Block IP at WAF (manual)','Add to watchlist (auto)','Notify SOC (auto)']],['Standard Analyst Triage','Medium-confidence alert correlation',['Log for SOC review (auto)','Add to triage queue (auto)']],['Monitor Only','Low-confidence activity',['Log for visibility (auto)']]]
const rules=[['LOGIN_BRUTE_FORCE','3+ failed logins within 60s from one IP','Brute-force alert','12,481'],['CREDENTIAL_STUFFING','2+ distinct usernames failed from one IP within 60s','Credential stuffing alert','4,208'],['MULTI_STAGE_CORRELATION','2+ distinct attack types from one IP within 120s','Multi-stage attack alert','1,862'],['PATH_TRAVERSAL','blocked traversal attempt on target-app','alert','932'],['SUSPICIOUS_FILE_UPLOAD','disallowed file extension uploaded','alert','317']]
function StateBadge({ value }: { value: string }) { const normalized=value.toLowerCase().replaceAll(' ','_'); const color=normalized.includes('success')||normalized.includes('online')||normalized.includes('automated')||normalized.includes('clean')?COLORS.success:normalized.includes('pending')||normalized.includes('approval')?COLORS.pending:normalized.includes('review')?'#60a5fa':normalized.includes('failed')||normalized.includes('offline')||normalized.includes('rejected')||normalized.includes('dismissed')?COLORS.critical:normalized.includes('manual')||normalized.includes('unknown')?COLORS.medium:'#2dd4bf'; return <span className="state-badge" style={{color,borderColor:`${color}55`,background:`${color}12`}}>{value}</span> }
function SimpleTable({title,headers,rows,extra,titleActions,rightAlignCols,statusCol=2,colWidths}:{title:string;headers:string[];rows:string[][];extra?:React.ReactNode;titleActions?:React.ReactNode;rightAlignCols?:number[];statusCol?:number;colWidths?:(string|undefined)[]}){const statusWords=['Critical','High','Medium','Low','Malicious','Suspicious','Clean','Unknown','Online','Offline','Registered','Success','Failed','Dismissed','Automated','Manual','Approval Required','Pending Approval','Approved','Executed','Review','Reviewed','Rejected','PENDING APPROVAL','APPROVED','EXECUTED','REVIEW','REJECTED'];const cellStyle=(j:number)=>({...(rightAlignCols?.includes(j)?{textAlign:'right' as const}:{}),...(colWidths?.[j]?{width:colWidths[j]}:{})});return <><div className="page-title"><div><div className="eyebrow">OPERATIONS / SECURITY DATA</div><h1>{title}</h1></div>{titleActions && <div className="title-actions">{titleActions}</div>}</div>{extra}<div className="table-panel"><table><thead><tr>{headers.map((h,j)=><th key={h} style={cellStyle(j)}>{h}</th>)}</tr></thead><tbody>{rows.map((r,i)=><tr key={i}>{r.map((v,j)=><td key={j} className={j===0?'mono':''} style={cellStyle(j)}>{j===0&&['Critical','High','Medium','Low'].includes(v)?<SeverityBadge severity={v}/>:j===statusCol&&['Malicious','Suspicious','Clean','Unknown'].includes(v)?<SeverityBadge severity={v}/>:statusWords.includes(v)&&(!['Critical','High','Medium','Low'].includes(v))?<StateBadge value={v}/>:v}</td>)}</tr>)}{rows.length===0 && <tr><td colSpan={headers.length} className="muted" style={{textAlign:'center',padding:'28px 0'}}>No data yet.</td></tr>}</tbody></table></div></>}
// What makes this tab worth having next to Alerts: Alerts is a flat,
// per-event list; Incidents is the correlated view -- one row per
// multi-alert attack thread from the same source IP (see backend/main.py's
// INCIDENT_CORRELATION_WINDOW_SECONDS grouping). The KPIs below and the
// severity/status/search filtering (reusing the same FilterMenu built for
// Alerts) are what actually earn it a separate tab instead of just being
// a duplicate table.
function Incidents(){
  const [data,setData]=useState<ApiIncident[]|null>(null)
  const [apiError,setApiError]=useState(false)
  const [query,setQuery]=useState('')
  const [severityFilter,setSeverityFilter]=useState<Set<string>>(new Set())
  const [pendingOnly,setPendingOnly]=useState(false)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiIncident[]>('/incidents').then(d=>{ if(!cancelled) setData(d) })
      .catch(()=>{ if(!cancelled){ setApiError(true); setData(null) } })
    return ()=>{ cancelled=true }
  },[])
  const list = data ?? []
  const toggleSeverity = (s:string) => setSeverityFilter(prev=>{ const next=new Set(prev); next.has(s)?next.delete(s):next.add(s); return next })
  const filtered = useMemo(()=>list.filter(inc=>
    (severityFilter.size===0 || severityFilter.has(inc.max_severity))
    && (!pendingOnly || inc.any_pending_approval)
    && (!query.trim() || `INC-${String(inc.incident_id).padStart(4,'0')} ${inc.ip} ${inc.mitre_techniques.join(' ')}`.toLowerCase().includes(query.trim().toLowerCase()))
  ),[list,severityFilter,pendingOnly,query])
  const criticalCount = list.filter(i=>i.max_severity==='Critical').length
  const pendingCount = list.filter(i=>i.any_pending_approval).length
  const avgAlerts = list.length ? (list.reduce((sum,i)=>sum+i.alert_count,0)/list.length).toFixed(1) : '0.0'
  const rows: string[][] = data ? filtered.map(inc=>[
    inc.max_severity,
    `INC-${String(inc.incident_id).padStart(4,'0')}`,
    inc.ip,
    String(inc.alert_count),
    inc.mitre_techniques.length?inc.mitre_techniques.join(', '):'—',
    inc.any_pending_approval?'Pending Approval':'Reviewed',
    toLocalTime(inc.first_seen),
    toLocalTime(inc.last_seen),
  ]) : incidents
  const toolbar = <>
    <ApiNotice show={apiError}/>
    <div className="kpi-grid" style={{gridTemplateColumns:'1fr 1fr 1fr 1fr'}}>
      <Kpi label="Active incidents" value={String(list.length).padStart(2,'0')} change="live" color={COLORS.info}/>
      <Kpi label="Critical incidents" value={String(criticalCount).padStart(2,'0')} change="live" color={COLORS.critical}/>
      <Kpi label="Pending approval" value={String(pendingCount).padStart(2,'0')} change="live" color={COLORS.pending}/>
      <Kpi label="Avg alerts / incident" value={avgAlerts} change="live" color={COLORS.medium}/>
    </div>
    <div className="toolbar">
      <div className="search-box"><Search size={15}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search incident ID, IP or technique..."/></div>
      <FilterMenu label="Severity" count={severityFilter.size}>
        {SEVERITY_OPTIONS.map(s=><CheckboxRow key={s} checked={severityFilter.has(s)} onChange={()=>toggleSeverity(s)} label={<SeverityBadge severity={s}/>}/>)}
      </FilterMenu>
      <button className={`outline-btn ${pendingOnly?'selected':''}`} onClick={()=>setPendingOnly(p=>!p)} style={pendingOnly?{borderColor:COLORS.pending,color:'#e9d5ff'}:undefined}>Pending approval only</button>
    </div>
  </>
  return <SimpleTable title="Incidents" headers={['SEVERITY','INCIDENT ID','SOURCE IP','ALERT COUNT','MITRE TECHNIQUES','STATUS','FIRST SEEN','LAST SEEN']} rows={rows} extra={toolbar}/>
}
type ApiLookupResult = { type:string; value:string; reputation:string; score:number; country:string|null; related_alert_count:number; related_alert_ids:number[]; mitre_technique:string|null }
// Investigations remounts from scratch every time the sidebar nav switches
// away and back (the top-level <div key={active}> forces that), which used
// to wipe `history` on every navigation -- looked like "history doesn't
// work" even though the lookup itself was fine. Persisting it to
// localStorage (read once on mount, written on every update) survives that
// remount, and a page reload too.
const INVESTIGATION_HISTORY_KEY = 'soar_investigation_history'
function loadInvestigationHistory(): ApiLookupResult[] {
  try{
    const raw = localStorage.getItem(INVESTIGATION_HISTORY_KEY)
    return raw ? JSON.parse(raw) : []
  }catch{ return [] }
}
function Investigations(){
  const [q,setQ]=useState('185.220.101.42')
  const [result,setResult]=useState<ApiLookupResult|null>(null)
  // Starts empty (not read from localStorage in the initializer) so the
  // client's first render matches the server-rendered markup -- same
  // hydration-safety reason as the timezone/landing-tab prefs above.
  // Loaded from storage in the effect below instead, right after mount.
  const [history,setHistory]=useState<ApiLookupResult[]>([])
  const [loading,setLoading]=useState(false)
  const [apiError,setApiError]=useState(false)
  useEffect(()=>{ setHistory(loadInvestigationHistory()) },[])
  const runLookup=async(value:string)=>{
    const trimmed=value.trim()
    if(!trimmed) return
    setLoading(true); setApiError(false)
    const type = /^[0-9a-fA-F]{32,64}$/.test(trimmed) ? 'hash' : 'ip'
    try{
      const data = await fetchJSON<ApiLookupResult>(`/threat-intel/lookup?type=${type}&value=${encodeURIComponent(trimmed)}`)
      setResult(data)
      setHistory(h=>{
        const next=[data, ...h.filter(x=>x.value!==data.value)].slice(0,5)
        try{ localStorage.setItem(INVESTIGATION_HISTORY_KEY, JSON.stringify(next)) }catch{ /* ignore */ }
        return next
      })
    }catch{ setApiError(true); setResult(null) }
    finally{ setLoading(false) }
  }
  useEffect(()=>{ runLookup(q) },[]) // eslint-disable-line react-hooks/exhaustive-deps
  return <><div className="page-title"><div><div className="eyebrow">MONITOR / IOC LOOKUP</div><h1>Investigations</h1></div></div><div className="investigation-search"><Search size={15}/><input value={q} onChange={e=>setQ(e.target.value)} onKeyDown={e=>{if(e.key==='Enter') runLookup(q)}} placeholder="Search IP or file hash"/><button className="primary-btn" onClick={()=>runLookup(q)}>Lookup</button></div><ApiNotice show={apiError}/><Panel title={`Lookup result · ${q}`}>{loading && <p className="muted">Looking up…</p>}{!loading && result && <div className="ioc-result"><div className="ioc-field reputation"><span>Reputation</span><SeverityBadge severity={result.reputation}/></div><div className="ioc-field"><span>Type</span><strong>{result.type.toUpperCase()}</strong></div><div className="ioc-field"><span>Country</span><strong>{result.country || '—'}</strong></div><div className="ioc-field alert-count"><span>Related alerts</span><strong>{result.related_alert_count}</strong></div><div className="chips">{result.related_alert_ids.length ? result.related_alert_ids.slice(0,5).map(id=><span key={id}>ALT-{id}</span>) : <span>No matches in stored alerts</span>}</div></div>}{!loading && !result && !apiError && <p className="muted">Enter an IP or hash and press Lookup.</p>}</Panel><div className="investigation-lower"><Panel title="Related entities"><div className="entity-list"><div><span>MITRE technique</span><strong className="mono">{result?.mitre_technique || '—'}</strong></div><div><span>Reputation score</span><strong>{result?.score ?? '—'}</strong></div><div><span>Related alerts</span><strong>{result?.related_alert_count ?? '—'}</strong></div></div></Panel><Panel title="Lookup history"><div className="entity-list">{history.length===0 && <p className="muted">No lookups yet this session.</p>}{history.map(h=><div key={h.value}><span className="mono">{h.value}</span><strong>{h.reputation} · {h.related_alert_count} alerts</strong></div>)}</div></Panel></div></>}
type ApiPlaybook = { key:string; name:string; steps:{action:string;auto:boolean}[]; times_triggered:number }
function Playbooks(){
  const [data,setData]=useState<ApiPlaybook[]|null>(null)
  const [apiError,setApiError]=useState(false)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiPlaybook[]>('/playbooks').then(d=>{ if(!cancelled) setData(d) }).catch(()=>{ if(!cancelled){ setApiError(true); setData(null) } })
    return ()=>{ cancelled=true }
  },[])
  const list = data ?? playbooks.map(([name,,steps])=>({ key:name as string, name:name as string, steps:(steps as string[]).map(s=>({action:s.replace(' (auto)','').replace(' (manual)',''),auto:s.endsWith('(auto)')})), times_triggered:0 }))
  return <><div className="page-title"><div><div className="eyebrow">AUTOMATE / RESPONSE LIBRARY</div><h1>Playbooks</h1></div></div><ApiNotice show={apiError}/><div className="playbook-grid">{list.map(pb=><Panel title={pb.name} action={data?`${pb.times_triggered} triggered`:undefined} key={pb.key}><div className="flow">{pb.steps.map((s,i)=><div className="flow-step" key={i}><i className={s.auto?'auto':''}/><span>{s.action}</span><small>{s.auto?'AUTO':'MANUAL'}</small></div>)}</div></Panel>)}</div></>}
type RunbookEntry = { key:string; name:string; severity:Severity; mitre:string; definition:string; indicators:string[]; steps:string[]; escalation:string }
// Static reference content, not fetched from the backend -- this is a
// learning/reference tab (definitions + what an analyst does by hand),
// not live data, so it's authored here once. Keyed to line up with the
// same attack types already surfaced elsewhere (Detection Rules' rule_key
// list and Playbooks' playbook names) so an analyst who just saw an alert
// for e.g. "Path Traversal" can find the matching entry by the same name.
const RUNBOOK_ENTRIES: RunbookEntry[] = [
  {
    key: 'brute_force', name: 'Brute Force Attack', severity: 'High', mitre: 'T1110 — Brute Force',
    definition: 'Repeated automated login attempts against one account or service from a single source, trying to guess a valid password by volume rather than by exploiting a flaw.',
    indicators: [
      '3+ failed logins within 60 seconds from the same source IP — this is exactly what the LOGIN_BRUTE_FORCE detection rule fires on.',
      'Failed attempts against the same username, back-to-back, with no successful login in between.',
      'Login attempts arriving faster than a human could type them.',
    ],
    steps: [
      "Confirm the alert: open the source IP and target account in Investigations and check whether any attempt actually succeeded.",
      'Lock the targeted account immediately, even if every attempt failed, to close the window.',
      "Block the source IP at the firewall / WAF so further attempts don't reach the login endpoint at all.",
      'Force a password reset for the account once unlocked, and enable MFA if it isn’t already on.',
      'Check whether the same source IP touched any other account (a sign of credential stuffing, not just brute force) before closing the alert.',
      'Notify the SOC lead and log the outcome in the Audit trail (analyst name, action taken, timestamp).',
    ],
    escalation: 'Escalate immediately if the login succeeded at any point — treat it as a confirmed account compromise, not just an attempted one.',
  },
  {
    key: 'credential_stuffing', name: 'Credential Stuffing', severity: 'High', mitre: 'T1110.004 — Credential Stuffing',
    definition: 'An attacker tries a list of previously-leaked username/password pairs from some other breach against this system, hoping people reused passwords.',
    indicators: [
      '2+ distinct usernames failing from the same source IP within 60 seconds — the CREDENTIAL_STUFFING detection rule.',
      'Attempts spread across many different accounts instead of hammering one account like brute force does.',
      'Request pattern that looks scripted (identical timing, identical headers).',
    ],
    steps: [
      "Pull the full list of usernames the source IP touched — every one is a candidate for a leaked-credential compromise, not just the ones that succeeded.",
      'Block the source IP immediately.',
      'Force a password reset on every account the IP attempted, whether or not that specific attempt succeeded.',
      "Cross-check any successful logins against that account's normal location/device — a login from a new device right after a stuffing attempt is a strong compromise signal.",
      'Recommend enabling MFA org-wide if this is a repeat pattern.',
      'Log the full list of affected accounts in the audit trail for follow-up.',
    ],
    escalation: 'Escalate to the incident response lead if any attempt succeeded — a successful hit usually means the password is reused and already known outside this org.',
  },
  {
    key: 'multi_stage', name: 'Multi-Stage / Correlated Attack', severity: 'Critical', mitre: 'Multiple — varies by stage',
    definition: 'The same source IP triggers two or more different attack types within a short window — e.g. a scan followed by a brute-force attempt — which usually means a deliberate, targeted attacker working through stages rather than random noise.',
    indicators: [
      '2+ distinct attack types from the same IP within 120 seconds — the MULTI_STAGE_CORRELATION detection rule.',
      'The IP shows up across multiple alert types in Incidents, not just one.',
      'Escalating severity over time from the same source.',
    ],
    steps: [
      'Treat this as one incident, not several unrelated alerts — open Incidents and review the full correlated timeline for that source IP.',
      'Isolate any asset the IP successfully reached during the sequence.',
      "Block the source IP at the perimeter immediately — don't wait for the next stage.",
      'Walk back through every stage (recon, then credential attempt, then whatever came next) and reverse anything that stuck — locked accounts, quarantined files, etc.',
      'Page the on-call analyst / SOC lead — multi-stage activity from one source is the strongest signal of an active, motivated attacker.',
      'Document each stage separately in the audit log so the full attack chain is reconstructable later.',
    ],
    escalation: 'Always escalate — this pattern is specifically designed to catch attacks too coordinated to be a false positive.',
  },
  {
    key: 'path_traversal', name: 'Path Traversal', severity: 'High', mitre: 'T1190 — Exploit Public-Facing Application',
    definition: 'An attacker manipulates a file-path parameter (e.g. ../../etc/passwd) to make the application read or write files outside the folder it should be limited to.',
    indicators: [
      'A blocked traversal attempt on target-app — the PATH_TRAVERSAL detection rule. Look for ../ sequences, encoded variants (%2e%2e%2f), or absolute paths where only a filename was expected.',
      'Requests probing for common sensitive files (passwd, web.config, .env).',
      'Repeated attempts with slightly different encodings from the same source — usually means the first one got blocked and they’re trying to evade the filter.',
    ],
    steps: [
      "Confirm the request was actually blocked and didn't return file contents — check the response, not just the request.",
      'Block the source IP at the WAF.',
      "Review the application's input validation for that endpoint — if this got through even partially, that's a real vulnerability, not just an attack attempt.",
      'Add the pattern to the watchlist so a repeat attempt from a different IP is caught immediately.',
      'Notify the dev / app-owner team so the endpoint gets a permanent fix, not just a perimeter block.',
      'Log the finding, including whether any file content was actually exposed.',
    ],
    escalation: "Escalate immediately if any file content was returned in the response — that's a confirmed data exposure, not just an attempt.",
  },
  {
    key: 'suspicious_upload', name: 'Suspicious File Upload', severity: 'High', mitre: 'T1105 — Ingress Tool Transfer',
    definition: 'A file with a disallowed or dangerous extension (e.g. .php, .exe, .jsp) is uploaded through a form only meant to accept things like images or documents — the classic first step toward planting a web shell.',
    indicators: [
      'A disallowed file extension uploaded — the SUSPICIOUS_FILE_UPLOAD detection rule.',
      'An upload immediately followed by a request trying to access or execute that same file.',
      "File content that doesn't match its declared extension (e.g. a .jpg that's actually a script).",
    ],
    steps: [
      'Quarantine the uploaded file immediately — do not open or execute it, even to inspect it, outside an isolated sandbox.',
      'Check the upload folder and web server logs for any request that tried to access or execute the uploaded file.',
      'If the file was ever reachable or executable, isolate the host and treat it as a likely compromise, not just an attempt.',
      "Submit the file's hash to a threat-intel lookup (VirusTotal) to confirm what it actually is.",
      'Tighten the upload validation — extension, content-type, and magic-byte checks — so this class of file can’t be accepted again.',
      'Log the action and notify the app owner.',
    ],
    escalation: 'Escalate immediately if the file was ever executed or reachable — treat the host as compromised until proven otherwise.',
  },
  {
    key: 'malware_ransomware', name: 'Malware / Ransomware', severity: 'Critical', mitre: 'T1486 — Data Encrypted for Impact',
    definition: 'Malicious software has run on a host — anything from a dropper to full ransomware — usually confirmed by a malicious file hash, unexpected process behavior, or a known-bad IP being contacted for command-and-control.',
    indicators: [
      'A Malicious verdict from a hash reputation lookup on a file present on the host.',
      'Unexpected outbound connections to a known-malicious IP shortly after a file executed.',
      'Sudden mass file-renaming/encryption activity, or a ransom note appearing on disk.',
    ],
    steps: [
      'Isolate the affected host from the network immediately — this is the single most important step, and comes before investigation, not after.',
      "Kill the malicious process if it's still running, only after isolation so it can't spread further first.",
      'Quarantine the file hash so nothing else on the network can execute the same file.',
      'Block any related IPs the malware was communicating with.',
      'Page the on-call analyst / IR lead — this severity does not wait for the next shift.',
      'Preserve a forensic snapshot of the host before any cleanup, so the infection can be analyzed after containment.',
      "Only begin remediation (reimage, restore from a clean backup) once the scope is fully understood — don't rush this step.",
    ],
    escalation: 'Always escalate to the incident response lead and, if ransomware is confirmed, to management immediately — this has business-continuity and possibly legal/disclosure implications.',
  },
  {
    key: 'recon_scanning', name: 'Reconnaissance / Port Scanning', severity: 'Low', mitre: 'T1595 — Active Scanning',
    definition: "Someone is probing the network — port scans, broad discovery requests — to map out what's running and what might be vulnerable, before deciding what to actually attack.",
    indicators: [
      'A single source hitting many ports or many hosts in a short window with no legitimate reason to.',
      "Connection attempts to ports that shouldn't be exposed at all.",
      'Traffic that looks automated/tooled — Nmap-style timing, sequential port order.',
    ],
    steps: [
      "Add the source IP to the watchlist so anything it does next is flagged automatically.",
      "Rate-limit or throttle traffic from that IP rather than an outright block, unless it's clearly hostile and external.",
      'Log the scan for correlation — reconnaissance is often the first stage of something bigger, so this record matters if a related alert shows up later (see Multi-Stage above).',
      "Check whether it found anything it shouldn't have — review what ports/services actually responded.",
      'No need to page anyone for a single scan — but repeated scanning from the same source over multiple days should get escalated.',
    ],
    escalation: "Low urgency on its own — escalate only if it's followed by a second attack type from the same source, or if it's targeted and repeated rather than broad and opportunistic.",
  },
  {
    key: 'data_exfiltration', name: 'Data Exfiltration', severity: 'Critical', mitre: 'T1041 — Exfiltration Over C2 Channel',
    definition: 'An unusually large volume of data is leaving the network toward an external destination — the sign that an attacker (or a compromised insider process) is actually taking data out, not just poking around.',
    indicators: [
      'Outbound data volume far above that host’s normal baseline.',
      'A large transfer to a destination the host has never talked to before.',
      "Transfer timing that doesn't match normal business use (e.g. a large upload at 3am).",
    ],
    steps: [
      'Isolate the host immediately to stop the transfer from continuing.',
      'Block the outbound destination IP.',
      'Snapshot the host for forensics before any cleanup, so what left the network can actually be determined.',
      'Identify what data was on the host and assess sensitivity — this determines whether it becomes a disclosure/compliance event.',
      'Page the on-call analyst / IR lead immediately.',
      'Preserve network flow logs covering the transfer window for the post-incident investigation.',
    ],
    escalation: 'Always escalate immediately, and loop in compliance/legal if the data involved may be regulated (PII, financial, health).',
  },
]
// Reference tab: definitions + step-by-step manual response per attack
// type, for an analyst to read and learn from -- distinct from the
// Playbooks tab above, which shows the automated orchestration flow
// (auto vs manual steps) actually wired into the response engine. This
// one is pure static content (no backend call), a list-and-detail layout
// so an analyst can scan attack names on the left and read the full
// procedure on the right without the page re-flowing underneath them.
function Runbook(){
  const [activeKey,setActiveKey]=useState(RUNBOOK_ENTRIES[0].key)
  const active = RUNBOOK_ENTRIES.find(e=>e.key===activeKey) || RUNBOOK_ENTRIES[0]
  return <>
    <div className="page-title"><div><div className="eyebrow">AUTOMATE / KNOWLEDGE BASE</div><h1>Runbook</h1></div></div>
    <p className="muted" style={{margin:'-10px 0 16px',maxWidth:760}}>What a SOC analyst does by hand for each attack type — definitions, how to recognize it, and the immediate manual response steps. A learning/reference guide, separate from the automated Playbooks tab.</p>
    <div className="runbook-layout">
      <div className="runbook-list">
        {RUNBOOK_ENTRIES.map(e=><button key={e.key} className={`runbook-list-item ${e.key===activeKey?'active':''}`} onClick={()=>setActiveKey(e.key)}>
          <SeverityBadge severity={e.severity}/><span>{e.name}</span>
        </button>)}
      </div>
      <div className="runbook-detail">
        <div className="runbook-detail-head">
          <div><div className="eyebrow">{active.mitre}</div><h2>{active.name}</h2></div>
          <SeverityBadge severity={active.severity}/>
        </div>
        <p className="runbook-definition">{active.definition}</p>
        <div className="runbook-section">
          <h3>How to recognize it</h3>
          <ul className="runbook-indicators">{active.indicators.map((ind,i)=><li key={i}>{ind}</li>)}</ul>
        </div>
        <div className="runbook-section">
          <h3>Immediate manual response steps</h3>
          <ol className="runbook-steps">{active.steps.map((s,i)=><li key={i}><span className="runbook-step-num">{i+1}</span><span>{s}</span></li>)}</ol>
        </div>
        <div className="runbook-escalation"><ShieldAlert size={15}/><span>{active.escalation}</span></div>
      </div>
    </div>
  </>
}
type ApiIoc = { value:string; type:string; reputation:string; count:number }
function ThreatIntel(){
  const [rows,setRows]=useState<string[][]|null>(null)
  const [apiError,setApiError]=useState(false)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiIoc[]>('/threat-intel/iocs').then(d=>{ if(!cancelled) setRows(d.map(x=>[x.value,x.type,x.reputation,String(x.count)])) }).catch(()=>{ if(!cancelled){ setApiError(true); setRows(iocs.map(r=>[r[0],r[1],r[2],r[4]])) } })
    return ()=>{ cancelled=true }
  },[])
  return <><ApiNotice show={apiError}/><SimpleTable title="Threat Intelligence" headers={['IOC VALUE','TYPE','REPUTATION','RELATED ALERT COUNT']} rows={rows ?? []}/></>
}

// GET /threat-intel/geo shape (backend/main.py geolocates every stored
// alert's IP via ip-api.com and rolls it up per country).
type ApiGeo = { country:string; lat:number|null; lon:number|null; attacks:number; unique_ips:number; severity:string }
const mockGeo: ApiGeo[] = [
  { country:'Russia', lat:60, lon:100, attacks:95, unique_ips:48, severity:'Critical' },
  { country:'United States', lat:39, lon:-98, attacks:71, unique_ips:36, severity:'High' },
  { country:'India', lat:21, lon:78, attacks:52, unique_ips:26, severity:'High' },
  { country:'Germany', lat:51, lon:10, attacks:34, unique_ips:17, severity:'Medium' },
  { country:'China', lat:35, lon:104, attacks:61, unique_ips:31, severity:'Critical' },
  { country:'Netherlands', lat:52, lon:5, attacks:23, unique_ips:12, severity:'Medium' },
]
// Great-circle test: is (lon,lat) on the hemisphere currently facing the
// viewer, given the orthographic projection's current [longitude,
// latitude, roll] rotation? Without this, markers on the far side of the
// globe would render right through it instead of being hidden.
function isFrontFacing(lon:number, lat:number, rotation:[number,number,number]): boolean {
  const toRad=(d:number)=>d*Math.PI/180
  const centerLon=-rotation[0], centerLat=-rotation[1]
  const λ1=toRad(lon), φ1=toRad(lat), λ2=toRad(centerLon), φ2=toRad(centerLat)
  const cosC=Math.sin(φ1)*Math.sin(φ2)+Math.cos(φ1)*Math.cos(φ2)*Math.cos(λ1-λ2)
  return cosC > -0.05
}
const TIME_OPTIONS: {label:string; hours:number|null}[] = [
  { label:'Last 24 hours', hours:24 },
  { label:'Last 7 days', hours:24*7 },
  { label:'All time', hours:null },
]
function ThreatMap(){
  const [geoData,setGeoData]=useState<ApiGeo[]|null>(null)
  const [apiError,setApiError]=useState(false)
  const [selected,setSelected]=useState<string|null>(null)
  const [severityFilter,setSeverityFilter]=useState<Set<string>>(new Set())
  const [hoursFilter,setHoursFilter]=useState<number|null>(null)
  // Orthographic "globe" rotation, driven by cursor position over the map
  // (see handleGlobeMove below). Starts tilted slightly north so it reads
  // as a globe rather than a flat disc before the user ever moves the
  // mouse over it.
  const [rotation,setRotation]=useState<[number,number,number]>([0,-15,0])
  const rafRef=useRef<number|null>(null)
  useEffect(()=>{
    let cancelled=false
    const qs = hoursFilter!=null ? `?hours=${hoursFilter}` : ''
    fetchJSON<ApiGeo[]>(`/threat-intel/geo${qs}`).then(data=>{ if(!cancelled) setGeoData(data) }).catch(()=>{ if(!cancelled){ setApiError(true); setGeoData(null) } })
    return ()=>{ cancelled=true }
  },[hoursFilter])
  const toggleSeverity = (s:string) => setSeverityFilter(prev=>{ const next=new Set(prev); next.has(s)?next.delete(s):next.add(s); return next })
  const source = geoData ?? mockGeo
  const list = useMemo(()=>source.filter(g=>severityFilter.size===0 || severityFilter.has(g.severity)),[source,severityFilter])
  const plottable = list.filter(g=>g.lat!=null && g.lon!=null)
  const frontFacing = plottable.filter(g=>isFrontFacing(g.lon as number, g.lat as number, rotation))
  const selectedRow = list.find(g=>g.country===selected)
  const handleGlobeMove = (e:React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const px = (e.clientX-rect.left)/rect.width - 0.5
    const py = (e.clientY-rect.top)/rect.height - 0.5
    if (rafRef.current!=null) return
    rafRef.current = requestAnimationFrame(()=>{
      setRotation([px*-150, Math.max(-55,Math.min(55, py*-80-15)), 0])
      rafRef.current = null
    })
  }
  const handleGlobeLeave = () => setRotation([0,-15,0])
  return <><div className="page-title"><div><div className="eyebrow">INTELLIGENCE / GLOBAL TELEMETRY</div><h1>Global Threat Map</h1></div></div><ApiNotice show={apiError}/>
    <Panel title="Attack origin by geography" className="map-panel">
      <div className="map-wrap globe-wrap" onMouseMove={handleGlobeMove} onMouseLeave={handleGlobeLeave}>
        <ComposableMap projection="geoOrthographic" projectionConfig={{ scale:210, rotate:rotation }} width={800} height={460}>
          <defs>
            <radialGradient id="oceanGradient" cx="35%" cy="30%" r="75%">
              <stop offset="0%" stopColor="#20495d"/>
              <stop offset="100%" stopColor="#050d12"/>
            </radialGradient>
          </defs>
          <circle cx={400} cy={230} r={210} fill="url(#oceanGradient)" stroke="#3a5a6c" strokeWidth={1}/>
          <Geographies geography={world}>{({geographies})=>geographies.map(g=><Geography key={g.rsmKey} geography={g} fill="#2c3d47" stroke="#5c7482" strokeWidth={0.4}/>)}</Geographies>
          {frontFacing.map(g=>{const radius=Math.max(3,Math.min(11,Math.sqrt(g.attacks)*1.1));const isSelected=selected===g.country;return <Marker key={g.country} coordinates={[g.lon as number,g.lat as number]} onClick={()=>setSelected(g.country)} onMouseEnter={()=>setSelected(g.country)}><circle className={`map-marker ${isSelected?'is-selected':''}`} r={radius} fill={COLORS[g.severity.toLowerCase() as keyof typeof COLORS] || COLORS.info} fillOpacity={.85} stroke="#fff" strokeWidth={isSelected?2:1}/><text className="map-label" x={radius+6} y={4} fill="#e7eef2" fontSize="8">{g.country}</text></Marker>})}
        </ComposableMap>
        <span className="map-note">Move your cursor over the globe to rotate it; click or hover a marker for details.</span>
      </div>
    </Panel>
    <div className="map-lower">
      <Panel title="Top Countries">
        <div className="country-list">{list.map(g=>{const c=COLORS[g.severity.toLowerCase() as keyof typeof COLORS] || COLORS.info; return <div className={selected===g.country?'is-selected':''} key={g.country} onClick={()=>setSelected(g.country)} style={{borderLeft:`3px solid ${c}`,paddingLeft:10}}><b>{g.country}</b><span style={{color:c}}>{g.attacks} attacks · {g.unique_ips} unique IPs</span></div>})}
        {list.length===0 && <p className="muted">No countries match the current filters.</p>}
        </div>
      </Panel>
      <Panel title={selected?`${selected} detail`:'Filters'}>
        <div className="filter-stack">
          <FilterMenu label="Severity" count={severityFilter.size}>
            {SEVERITY_OPTIONS.map(s=><CheckboxRow key={s} checked={severityFilter.has(s)} onChange={()=>toggleSeverity(s)} label={<SeverityBadge severity={s}/>}/>)}
          </FilterMenu>
          <FilterMenu label={TIME_OPTIONS.find(t=>t.hours===hoursFilter)?.label ?? 'All time'}>
            {TIME_OPTIONS.map(t=><CheckboxRow key={t.label} checked={hoursFilter===t.hours} onChange={()=>setHoursFilter(t.hours)} label={t.label}/>)}
          </FilterMenu>
          {selectedRow&&<p className="muted">Total attacks {selectedRow.attacks} · {selectedRow.unique_ips} unique IPs<br/>Severity level: {selectedRow.severity}{selectedRow.lat==null && <><br/>No coordinates (internal/unresolvable IPs)</>}</p>}
        </div>
      </Panel>
    </div>
  </>}
type ApiAsset = { hostname:string; ip:string|null; mac_address:string|null; owner:string|null; type:string; status:string; risk_score:number; active_incidents:number; max_severity:string|null; alert_count:number; last_seen:string }

// Generic centered form dialog -- distinct from the side Drawer, used for
// "Add Asset" (and any future create/edit form) since a form reads better
// centered than pinned to the screen edge.
function Modal({ title, onClose, children }: { title:string; onClose:()=>void; children:React.ReactNode }) {
  return <>
    <button className="modal-backdrop" aria-label="Close dialog" onClick={onClose}/>
    <div className="modal-panel" role="dialog" aria-modal="true">
      <div className="modal-head"><h3>{title}</h3><button className="icon-btn" onClick={onClose}><X size={18}/></button></div>
      <div className="modal-body">{children}</div>
    </div>
  </>
}

// "Add Asset" -- registers a real LAN device/employee record ahead of the
// LAN-monitoring review milestone. lan_ip/mac_address are auto-detected
// from GET /assets/detect when the dialog opens (the browser submitting
// this form IS the device being registered, so the backend can read its
// real connecting IP and look its MAC up from its own ARP table) rather
// than typed by hand; employee name, hostname and LAN IP are mandatory,
// everything else is optional.
function AddAssetModal({ onClose, onCreated }: { onClose:()=>void; onCreated:()=>void }) {
  const [employeeName,setEmployeeName]=useState('')
  const [hostname,setHostname]=useState('')
  const [lanIp,setLanIp]=useState('')
  const [macAddress,setMacAddress]=useState<string|null>(null)
  const [detecting,setDetecting]=useState(true)
  const [sshEnabled,setSshEnabled]=useState(false)
  const [department,setDepartment]=useState('')
  const [notes,setNotes]=useState('')
  const [submitting,setSubmitting]=useState(false)
  const [error,setError]=useState<string|null>(null)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<{lan_ip:string|null; mac_address:string|null}>('/assets/detect').then(d=>{
      if(cancelled) return
      if(d.lan_ip) setLanIp(d.lan_ip)
      setMacAddress(d.mac_address)
    }).catch(()=>{}).finally(()=>{ if(!cancelled) setDetecting(false) })
    return ()=>{ cancelled=true }
  },[])
  const canSubmit = employeeName.trim() && hostname.trim() && lanIp.trim() && !submitting
  const submit = async () => {
    if(!canSubmit) return
    setSubmitting(true); setError(null)
    try{
      const res = await fetch(`${API_BASE}/assets`, {
        method:'POST', headers:{'content-type':'application/json'},
        body: JSON.stringify({ employee_name:employeeName.trim(), hostname:hostname.trim(), lan_ip:lanIp.trim(), mac_address:macAddress, ssh_enabled:sshEnabled, department:department.trim()||null, notes:notes.trim()||null }),
      })
      if(!res.ok){ const d = await res.json().catch(()=>({})); throw new Error(d.detail || `Failed (${res.status})`) }
      onCreated()
      onClose()
    }catch(err){ setError(err instanceof Error ? err.message : 'Failed to register asset.') }
    finally{ setSubmitting(false) }
  }
  return <Modal title="Add Asset" onClose={onClose}>
    <div className="field-grid">
      <label className="required">Employee name<input value={employeeName} onChange={e=>setEmployeeName(e.target.value)} placeholder="e.g. Priya Sharma"/></label>
      <label className="required">Hostname<input value={hostname} onChange={e=>setHostname(e.target.value)} placeholder="e.g. PRIYA-LAPTOP"/></label>
      <label className="required">LAN / Private IP<span className="auto-note">auto-detected</span><input value={lanIp} onChange={e=>setLanIp(e.target.value)} placeholder={detecting?'Detecting…':'e.g. 192.168.1.42'}/></label>
      <label>MAC address<span className="auto-note">auto-detected</span><input value={detecting?'Detecting…':(macAddress||'Not detected on this network')} readOnly/></label>
      <label>Department<input value={department} onChange={e=>setDepartment(e.target.value)} placeholder="optional"/></label>
      <label className="checkbox-field"><input type="checkbox" checked={sshEnabled} onChange={e=>setSshEnabled(e.target.checked)}/> Remote login (SSH) enabled</label>
      <label className="full">Notes<textarea value={notes} onChange={e=>setNotes(e.target.value)} placeholder="optional -- department, role, anything worth flagging"/></label>
    </div>
    {error && <p className="muted" style={{color:COLORS.critical,marginTop:10}}>{error}</p>}
    <div className="modal-actions">
      <button className="outline-btn" onClick={onClose}>Cancel</button>
      <button className="primary-btn" disabled={!canSubmit} onClick={submit}>{submitting?'Saving…':'Add Asset'}</button>
    </div>
  </Modal>
}

function Assets(){
  const [assets,setAssets]=useState<ApiAsset[]|null>(null)
  const [apiError,setApiError]=useState(false)
  const [showAdd,setShowAdd]=useState(false)
  const [refreshKey,setRefreshKey]=useState(0)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiAsset[]>('/assets').then(d=>{ if(!cancelled) setAssets(d) }).catch(()=>{ if(!cancelled){ setApiError(true); setAssets([]) } })
    return ()=>{ cancelled=true }
  },[refreshKey])
  const rows = (assets ?? []).map(a=>[a.hostname, a.ip||'—', a.mac_address||'—', a.owner||'—', a.type, a.status, String(a.risk_score), String(a.active_incidents), toLocalTime(a.last_seen)])
  return <><ApiNotice show={apiError}/>
    <SimpleTable
      title="Assets"
      headers={['ASSET / SOURCE','IP','MAC ADDRESS','OWNER','TYPE','STATUS','RISK SCORE','ACTIVE INCIDENTS','LAST SEEN']}
      rows={rows}
      rightAlignCols={[6,7]}
      statusCol={-1}
      titleActions={<button className="primary-btn" onClick={()=>setShowAdd(true)}><Plus size={15}/> Add Asset</button>}
    />
    {showAdd && <AddAssetModal onClose={()=>setShowAdd(false)} onCreated={()=>setRefreshKey(k=>k+1)}/>}
  </>
}
type ApiAuditRow = { id:number; timestamp:string; actor:string; action:string; target:string; source_ip:string|null; result:string }
function ResponseCenter(){
  const [alerts,setAlerts]=useState<Alert[]|null>(null)
  const [auditRows,setAuditRows]=useState<ApiAuditRow[]|null>(null)
  const [apiError,setApiError]=useState(false)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiAlert[]>('/alerts').then(d=>{ if(!cancelled) setAlerts(d.map(mapAlert)) }).catch(()=>{ if(!cancelled) setApiError(true) })
    fetchJSON<ApiAuditRow[]>('/audit').then(d=>{ if(!cancelled) setAuditRows(d) }).catch(()=>{ if(!cancelled){ setApiError(true); setAuditRows([]) } })
    return ()=>{ cancelled=true }
  },[])
  const list = alerts ?? []
  const tiles = [
    ['Alerts ingested', String(list.length)],
    ['Auto-resolved', String(list.filter(a=>a.status==='auto_resolved').length)],
    ['Approved', String(list.filter(a=>a.status==='approved_and_executed').length)],
    ['Rejected', String(list.filter(a=>a.status==='rejected').length)],
    ['Pending approval', String(list.filter(a=>a.status==='pending_approval').length)],
  ]
  const responseRows = (auditRows ?? []).filter(r=>r.action==='Approved response'||r.action==='Rejected response').map(r=>[
    toLocalTime(r.timestamp), r.action, r.target, r.actor, r.result,
  ])
  return <><div className="page-title"><div><div className="eyebrow">OPERATIONS / SOAR</div><h1>Response Center</h1></div></div><ApiNotice show={apiError}/><div className="action-tiles">{tiles.map(x=><div className="action-tile" key={x[0]}><span>{x[0]}</span><strong>{x[1]}</strong></div>)}</div><SimpleTable title="Recent Actions" headers={['TIMESTAMP','ACTION','TARGET','TRIGGERED BY','RESULT']} rows={responseRows} colWidths={['130px','200px','110px','150px','140px']} statusCol={-1}/></>}
type ApiSshSession = { id:number; timestamp:string; host:string; port:number; username:string; success:boolean; output:string|null; error:string|null }
// Mirrors ssh_manager.py's DIAGNOSTIC_COMMANDS (whoami / hostname / uptime) --
// kept as a named constant instead of a bare "3" so it stays honest if that
// fixed command set ever changes on the backend.
const DIAGNOSTIC_COMMAND_COUNT = 3
// Shown only until a real /ssh/connect attempt is made (see tableRows below)
// -- same fallback-content pattern as mockAlerts, so the panel doesn't just
// show an empty "No data yet" table before anyone's tried it this session.
// Same fixed-anchor fix as mockAlerts above, and for the same reason: this
// is a module-level constant, so Date.now() would bake in a different
// timestamp on the server vs. the browser and cause a hydration mismatch
// the moment this tab is ever server-rendered.
const MOCK_SSH_SESSIONS: ApiSshSession[] = [
  { id:-1, timestamp:new Date(MOCK_ANCHOR_MS-3*3600_000).toISOString(), host:'10.20.4.11', port:22, username:'analyst', success:true, output:null, error:null },
  { id:-2, timestamp:new Date(MOCK_ANCHOR_MS-6*3600_000).toISOString(), host:'10.20.4.18', port:22, username:'analyst', success:false, output:null, error:'Connection timed out' },
  { id:-3, timestamp:new Date(MOCK_ANCHOR_MS-26*3600_000).toISOString(), host:'10.20.4.9', port:22, username:'root', success:true, output:null, error:null },
]
function SshSessions(){
  const [form,setForm]=useState({host:'10.20.4.18',port:'22',username:'analyst',password:''})
  const [output,setOutput]=useState<string|null>(null)
  const [error,setError]=useState<string|null>(null)
  const [connecting,setConnecting]=useState(false)
  const [sessions,setSessions]=useState<ApiSshSession[]|null>(null)
  const [apiError,setApiError]=useState(false)
  const loadSessions=()=>{
    fetchJSON<ApiSshSession[]>('/ssh/sessions').then(d=>setSessions(d)).catch(()=>{ setApiError(true); setSessions([]) })
  }
  useEffect(()=>{ loadSessions() },[])
  const set=(k:keyof typeof form)=>(e:React.ChangeEvent<HTMLInputElement>)=>setForm(f=>({...f,[k]:e.target.value}))
  const connect=async()=>{
    setConnecting(true); setError(null); setOutput(null)
    try{
      const res = await fetch(`${API_BASE}/ssh/connect`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ host:form.host, port:Number(form.port)||22, username:form.username, password:form.password||null }) })
      const data = await res.json()
      if(!res.ok) setError(data.detail || 'Connection failed'); else setOutput(data.output || '(connected, no output)')
    }catch{ setError(`Can't reach the backend at ${API_BASE}.`) }
    finally{ setConnecting(false); loadSessions() }
  }
  const sessionRows = (sessions && sessions.length>0) ? sessions : MOCK_SSH_SESSIONS
  const tableRows = sessionRows.map(s=>[`SSH-${s.id<0?`DEMO${-s.id}`:s.id}`, s.host, s.username, toLocalTime(s.timestamp), s.success?'Success':'Failed', s.success?String(DIAGNOSTIC_COMMAND_COUNT):'0'])
  return <><div className="page-title"><div><div className="eyebrow">OPERATIONS / REMOTE ACCESS</div><h1>SSH / Sessions</h1></div></div><div className="ssh-grid"><Panel title="Connect to host"><div className="form-stack"><label>Host<input value={form.host} onChange={set('host')}/></label><label>Port<input value={form.port} onChange={set('port')}/></label><label>Username<input value={form.username} onChange={set('username')}/></label><label>Password<input type="password" value={form.password} onChange={set('password')} placeholder="(if required)"/></label><button className="primary-btn" onClick={connect} disabled={connecting}><Terminal size={14}/> {connecting?'Connecting…':'Connect'}</button></div></Panel><Panel title="Live output" className="terminal-panel"><div className="terminal">{error ? <span style={{color:COLORS.critical}}>Error: {error}</span> : connecting ? <span className="muted">Connecting…</span> : output ? <pre style={{margin:0,fontFamily:'inherit',whiteSpace:'pre-wrap'}}>{output}</pre> : <span className="muted">Enter credentials for a host with SSH enabled and click Connect to view live output here.</span>}</div></Panel></div><ApiNotice show={apiError}/><SimpleTable title="Session log" headers={['SESSION ID','HOST','USERNAME','TIME','STATUS','COMMANDS RUN']} rows={tableRows} rightAlignCols={[5]} colWidths={['110px','140px','120px','150px','120px','130px']} statusCol={4}/></>}
function Audit(){
  const [rows,setRows]=useState<ApiAuditRow[]|null>(null)
  const [query,setQuery]=useState('')
  const [apiError,setApiError]=useState(false)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiAuditRow[]>('/audit').then(d=>{ if(!cancelled) setRows(d) }).catch(()=>{ if(!cancelled){ setApiError(true); setRows([]) } })
    return ()=>{ cancelled=true }
  },[])
  const filtered = (rows ?? []).filter(r=>`${r.actor} ${r.action} ${r.target}`.toLowerCase().includes(query.toLowerCase()))
  const tableRows = filtered.map(r=>[toLocalDateTime(r.timestamp), r.actor, r.action, r.target, r.source_ip||'—', r.result])
  return <><div className="page-title"><div><div className="eyebrow">SYSTEM / COMPLIANCE LOG</div><h1>Audit</h1></div><a className="outline-btn" href={`${API_BASE}/alerts/export.csv`} target="_blank" rel="noreferrer"><FileText size={14}/> Export alerts CSV</a></div><ApiNotice show={apiError}/><div className="toolbar"><div className="search-box"><Search size={15}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Filter user or action"/></div></div><SimpleTable title="Audit events" headers={['TIMESTAMP','ACTOR','ACTION','TARGET','SOURCE IP','RESULT']} rows={tableRows} colWidths={['150px',undefined,undefined,undefined,undefined,undefined]}/></>}
function Reports(){
  const [reports,setReports]=useState<ApiReport[]|null>(null)
  const [apiError,setApiError]=useState(false)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiReport[]>('/reports').then(data=>{ if(!cancelled) setReports(data) }).catch(()=>{ if(!cancelled){ setApiError(true); setReports([]) } })
    return ()=>{ cancelled=true }
  },[])
  const list = reports ?? []
  return <><div className="page-title"><div><div className="eyebrow">SYSTEM / GENERATED OUTPUT</div><h1>Reports</h1></div></div><ApiNotice show={apiError}/><div className="report-list">{list.length===0 && !apiError && <p className="muted" style={{padding:'16px 0'}}>No reports generated yet — this needs report-generator/generate_report.py running as its own process (it polls alerts every 20s and writes a PDF here whenever there are new ones; it doesn't start automatically with the backend).</p>}{list.map(r=><div className="report-row" key={r.filename}><FileText size={18}/><div><strong>{r.filename}</strong><span>Generated {formatReportTimestamp(r.generated_at)}</span></div><a className="outline-btn" href={`${API_BASE}${r.download_url}?downloaded_by=${encodeURIComponent(getCurrentAdminName()||'analyst')}`} target="_blank" rel="noreferrer">Download</a></div>)}</div></>}
// Same shape/endpoint pattern as Reports(), pointed at the separate
// report-generator/generate_daily_report.py process and its reports/daily/
// output -- one consolidated PDF every 24h, not the frequent per-cycle
// reports above, so they get their own tab rather than mixing into one list.
function DailyReport(){
  const [reports,setReports]=useState<ApiReport[]|null>(null)
  const [apiError,setApiError]=useState(false)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiReport[]>('/reports/daily').then(data=>{ if(!cancelled) setReports(data) }).catch(()=>{ if(!cancelled){ setApiError(true); setReports([]) } })
    return ()=>{ cancelled=true }
  },[])
  const list = reports ?? []
  return <><div className="page-title"><div><div className="eyebrow">SYSTEM / GENERATED OUTPUT</div><h1>24-Hour Report</h1></div></div><ApiNotice show={apiError}/><div className="report-list">{list.length===0 && !apiError && <p className="muted" style={{padding:'16px 0'}}>No 24-hour digest yet — this needs report-generator/generate_daily_report.py running as its own process (it writes one consolidated PDF covering the last 24 hours, then again every 24 hours; it doesn't start automatically with the backend, and it's separate from the per-cycle Reports tab).</p>}{list.map(r=><div className="report-row" key={r.filename}><FileClock size={18}/><div><strong>{r.filename}</strong><span>Generated {formatReportTimestamp(r.generated_at)}</span></div><a className="outline-btn" href={`${API_BASE}${r.download_url}?downloaded_by=${encodeURIComponent(getCurrentAdminName()||'analyst')}`} target="_blank" rel="noreferrer">Download</a></div>)}</div></>}
type ApiDetectionRule = { key:string; name:string; description:string; source:string; enabled:boolean; times_triggered:number }
// Short label shown in the CONDITION column, with the full sentence only
// a click away (see the modal below) -- generated from the real
// description text itself (first clause, capped) rather than a hand-typed
// lookup per rule, so it can't drift out of sync if the backend's wording
// ever changes.
function shortCondition(description:string): string {
  const delimiterIndex = description.search(/[,.]/)
  const firstClause = delimiterIndex > 0 ? description.slice(0, delimiterIndex) : description
  const truncatedToClause = firstClause.length < description.length
  const capped = firstClause.length > 46 ? firstClause.slice(0, 46).trimEnd() : firstClause
  return (truncatedToClause || capped.length < firstClause.length) ? `${capped}…` : capped
}
function DetectionRules(){
  const [ruleList,setRuleList]=useState<ApiDetectionRule[]|null>(null)
  const [apiError,setApiError]=useState(false)
  const [toggling,setToggling]=useState<string|null>(null)
  const [detailRule,setDetailRule]=useState<ApiDetectionRule|null>(null)
  useEffect(()=>{
    let cancelled=false
    fetchJSON<ApiDetectionRule[]>('/detection-rules').then(d=>{ if(!cancelled) setRuleList(d) }).catch(()=>{ if(!cancelled){ setApiError(true); setRuleList(null) } })
    return ()=>{ cancelled=true }
  },[])
  const list = ruleList ?? rules.map(r=>({ key:r[0], name:r[0], description:r[1], source:r[2], enabled:true, times_triggered:Number(r[3].replace(',','')) }))
  const total = list.reduce((sum,r)=>sum+r.times_triggered,0)
  const toggle = async (key:string) => {
    setToggling(key)
    try{
      const res = await fetch(`${API_BASE}/detection-rules/${key}/toggle`, { method:'POST' })
      const data = await res.json()
      if(res.ok) setRuleList(current=>(current ?? []).map(r=>r.key===key?{...r, enabled:data.enabled}:r))
    }catch{ /* backend unreachable — leave state as-is */ }
    finally{ setToggling(null) }
  }
  return <><div className="page-title"><div><div className="eyebrow">SYSTEM / DETECTION ENGINE</div><h1>Detection Rules</h1></div></div><ApiNotice show={apiError}/><div className="rules-stats"><div className="rule-stat"><span>Total rules</span><strong>{list.length}</strong></div><div className="rule-stat"><span>Combined triggers</span><strong>{total.toLocaleString()}</strong></div><div className="rule-stat"><span>Enabled</span><strong>{list.filter(r=>r.enabled).length}</strong></div></div><div className="table-panel"><table style={{tableLayout:'fixed'}}><colgroup><col style={{width:'190px'}}/><col/><col style={{width:'110px'}}/><col style={{width:'90px'}}/><col style={{width:'120px'}}/></colgroup><thead><tr>{['RULE NAME','CONDITION','SOURCE','ENABLED','TRIGGER COUNT'].map((h,j)=><th key={h} style={j===3?{textAlign:'center'}:j===4?{textAlign:'right'}:undefined}>{h}</th>)}</tr></thead><tbody>{list.map(r=><tr key={r.key}><td className="mono" style={{whiteSpace:'normal'}}>{r.name}</td><td style={{whiteSpace:'normal'}}><button className="condition-link" onClick={()=>setDetailRule(r)} title="Click for the full condition">{shortCondition(r.description)}</button></td><td>{r.source}</td><td style={{textAlign:'center'}}><button className={`toggle ${r.enabled?'':'off'}`} aria-label={`Toggle ${r.name}`} aria-pressed={r.enabled} disabled={toggling===r.key || !ruleList} onClick={()=>toggle(r.key)}/></td><td className="mono" style={{textAlign:'right'}}>{r.times_triggered.toLocaleString()}</td></tr>)}</tbody></table></div><p className="muted" style={{padding:'12px 0 0'}}>Toggling a rule here writes to the backend's shared enable/disable state; detection-agent polls it every few seconds and skips disabled rules on its next detection cycle.</p>{detailRule && <Modal title={detailRule.name} onClose={()=>setDetailRule(null)}><p style={{margin:'0 0 10px',color:'var(--dim)',fontSize:11,textTransform:'uppercase',letterSpacing:'.05em'}}>Source: {detailRule.source}</p><p style={{margin:0,lineHeight:1.6}}>{detailRule.description}</p></Modal>}</>}
type ApiIntegrationFailure = { timestamp:string; detail:string; context:string|null }
type ApiIntegration = { name:string; connected:boolean; detail:string; recent_failures?:ApiIntegrationFailure[] }
// Every real external call this backend makes -- AbuseIPDB, VirusTotal,
// ip-api.com geolocation, the Slack webhook -- so a fix here (a new
// integration wired in on the backend) has one obvious place on the
// frontend to add it too. Kept in sync manually with backend/main.py's
// integrations_status(); see that endpoint's docstring for why "verify
// nothing's missing" is a real, recurring check, not a one-time audit.
const INTEGRATIONS_REFRESH_MS = 30_000 // "regular check" -- see component comment below
function IntegrationDetailModal({ integration, onClose }: { integration:ApiIntegration; onClose:()=>void }) {
  const failures = integration.recent_failures ?? []
  return <Modal title={integration.name} onClose={onClose}>
    <p style={{margin:'0 0 4px',color:'var(--dim)',fontSize:11,textTransform:'uppercase',letterSpacing:'.05em'}}>Status</p>
    <p style={{margin:'0 0 14px'}}><span className={integration.connected?'connected':'disconnected'}><i/>{integration.connected?'Connected':'Not configured'}</span> — {integration.detail}</p>
    <p style={{margin:'0 0 8px',color:'var(--dim)',fontSize:11,textTransform:'uppercase',letterSpacing:'.05em'}}>Recent failures</p>
    {failures.length===0
      ? <p className="muted" style={{margin:0}}>No failed calls to this integration since the backend last started — "Connected" here just means it's configured; this is what shows whether the last real call to it actually worked.</p>
      : <div className="failure-list">{failures.map((f,i)=><div className="failure-row" key={i}><div className="failure-row-head"><strong>{toLocalDateTime(f.timestamp)}</strong>{f.context && <span className="mono">{f.context}</span>}</div><p>{f.detail}</p></div>)}</div>}
  </Modal>
}
function Integrations(){
  const [data,setData]=useState<ApiIntegration[]|null>(null)
  const [apiError,setApiError]=useState(false)
  const [checkedAt,setCheckedAt]=useState<string|null>(null)
  const [detail,setDetail]=useState<ApiIntegration|null>(null)
  // "Checked HH:MM:SS" used to be computed once on mount and then just sit
  // there looking live while going stale for as long as the tab stayed
  // open -- there was no actual "regular check" behind it, just a
  // one-time snapshot. This now genuinely re-polls on an interval, so the
  // timestamp (and any new integration failures) reflect the current
  // state, not just whatever was true the moment you opened the tab.
  useEffect(()=>{
    let cancelled=false
    const load=()=>{
      fetchJSON<ApiIntegration[]>('/integrations/status')
        .then(d=>{ if(cancelled) return; setData(d); setApiError(false); setCheckedAt(new Date().toLocaleTimeString([], { hour12:false })) })
        .catch(()=>{ if(!cancelled){ setApiError(true); setData(null) } })
    }
    load()
    const interval = setInterval(load, INTEGRATIONS_REFRESH_MS)
    return ()=>{ cancelled=true; clearInterval(interval) }
  },[])
  const list = data ?? []
  return <><div className="page-title"><div><div className="eyebrow">SYSTEM / CONNECTED SERVICES</div><h1>Integrations</h1></div></div><ApiNotice show={apiError}/><div className="integration-list">{list.map(x=>{ const failureCount=(x.recent_failures??[]).length; return <div className="integration-row" key={x.name}><div><strong>{x.name}</strong><span className={x.connected?'connected':'disconnected'}><i/>{x.connected?'Connected':'Not configured'}</span>{failureCount>0 && <button className="integration-issue" onClick={()=>setDetail(x)}><AlertTriangle size={11}/> {failureCount} recent failure{failureCount===1?'':'s'}</button>}</div><small className="integration-last-checked" title={x.detail}>{checkedAt ? `Checked ${checkedAt}` : 'Checking…'}</small></div> })}</div><p className="muted" style={{padding:'12px 0 0'}}>Re-checked automatically every {INTEGRATIONS_REFRESH_MS/1000}s. "Connected" means the API key/webhook is configured -- click a "recent failures" flag to see exactly what broke on an actual call and when.</p>{detail && <IntegrationDetailModal integration={detail} onClose={()=>setDetail(null)}/>}</>}
// A dedicated admin panel is planned separately, so playbook
// auto-approval — a real security-relevant control — no longer lives here
// as a toggle with no backend behind it. Replaced with two settings that
// actually do something: timestamp display (every toLocalTime/
// toLocalDateTime call across the whole dashboard reads this) and which
// tab the dashboard opens on.
const TIMEZONE_OPTIONS: {value:'local'|'utc'; label:string}[] = [{value:'local', label:'Local Time'}, {value:'utc', label:'UTC'}]
const LANDING_TAB_OPTIONS = ['Overview','Alerts','Incidents']
function SettingsPage({light,setLight}:{light:boolean;setLight:(value:boolean)=>void}){
  const [notifyOnCritical,setNotifyOnCritical]=useState(true)
  const [tzPref,setTzPref]=useState<'local'|'utc'>(()=>getDisplayTimezone())
  const [landingTab,setLandingTab]=useState<string>(()=>{ try{ return localStorage.getItem(DEFAULT_TAB_KEY) || 'Overview' }catch{ return 'Overview' } })
  const chooseTimezone=(tz:'local'|'utc')=>{ setDisplayTimezone(tz); setTzPref(tz) }
  const chooseLandingTab=(tab:string)=>{ setDefaultLandingTab(tab); setLandingTab(tab) }
  return <>
    <div className="page-title"><div><div className="eyebrow">SYSTEM / PREFERENCES</div><h1>Settings</h1></div></div>
    {/* Preferences and Account used to sit directly next to each other with
       no gap between them -- .panel has no margin of its own (by design,
       so panels inside a CSS grid elsewhere don't get a doubled-up gap),
       so here, as plain vertical siblings with nothing else providing
       spacing, their borders touched and the two cards visually merged
       into one. This wrapper is the fix: an explicit gap for this one
       stacked-panels case. */}
    <div className="settings-stack">
      <Panel title="Preferences">
        <div className="setting-list">
          <div className="setting-row"><span>Email notifications on critical alerts</span><button className={`toggle ${notifyOnCritical?'':'off'}`} aria-pressed={notifyOnCritical} aria-label="Email notifications on critical alerts" onClick={()=>setNotifyOnCritical(v=>!v)}/></div>
          <div className="setting-row theme-setting"><div><span>Timestamp display</span><small>How times are shown across every tab</small></div><div className="theme-options">{TIMEZONE_OPTIONS.map(o=><button key={o.value} className={tzPref===o.value?'selected':''} onClick={()=>chooseTimezone(o.value)}>{o.label}</button>)}</div></div>
          <div className="setting-row theme-setting"><div><span>Default landing tab</span><small>Which page the dashboard opens on</small></div><div className="theme-options">{LANDING_TAB_OPTIONS.map(t=><button key={t} className={landingTab===t?'selected':''} onClick={()=>chooseLandingTab(t)}>{t}</button>)}</div></div>
          <div className="setting-row theme-setting"><div><span>Theme</span><small>Choose the workspace appearance</small></div><div className="theme-options"><button className={!light?'selected':''} onClick={()=>setLight(false)}>Dark</button><button className={light?'selected':''} onClick={()=>setLight(true)}>Light</button></div></div>
        </div>
      </Panel>
      <Panel title="Account"><div className="account-row"><span>SOC role</span><SeverityBadge severity="Analyst"/></div></Panel>
    </div>
  </>
}
type ApiAdmin = { id:number; name:string; company_id:string; role:string|null; session_id:number|null }
type ApiAdminSession = { id:number; admin_name:string; company_id:string; role:string|null; login_at:string; logout_at:string|null }
type ApiApprovalPolicy = { severity:Record<string,string>; playbook:Record<string,string> }
// "who's analyzing it now" + admin creation/login + per-severity/per-playbook
// approve policy + the two access logs the user asked for, all in one tab.
// currentAdmin/setCurrentAdmin are lifted up to Page() (not local state
// here) because the sidebar's bottom-left label and the Reports download
// link both need to read the signed-in admin from outside this component.
function AdminPanel({currentAdmin,setCurrentAdmin}:{currentAdmin:AdminInfo|null;setCurrentAdmin:(a:AdminInfo|null)=>void}){
  const [admins,setAdmins]=useState<ApiAdmin[]|null>(null)
  const [sessions,setSessions]=useState<ApiAdminSession[]|null>(null)
  const [auditRows,setAuditRows]=useState<ApiAuditRow[]|null>(null)
  const [policy,setPolicy]=useState<ApiApprovalPolicy|null>(null)
  const [apiError,setApiError]=useState(false)
  const [loginForm,setLoginForm]=useState({admin_id:'',password:''})
  const [loginError,setLoginError]=useState<string|null>(null)
  const [loggingIn,setLoggingIn]=useState(false)
  const [createForm,setCreateForm]=useState({name:'',company_id:'',role:'',password:''})
  const [createError,setCreateError]=useState<string|null>(null)
  const [creating,setCreating]=useState(false)
  const [loggingOut,setLoggingOut]=useState(false)
  const loadAll=()=>{
    fetchJSON<ApiAdmin[]>('/admin/list').then(d=>setAdmins(d)).catch(()=>{ setApiError(true); setAdmins([]) })
    fetchJSON<ApiAdminSession[]>('/admin/sessions').then(d=>setSessions(d)).catch(()=>{ setApiError(true); setSessions([]) })
    fetchJSON<ApiAuditRow[]>('/audit').then(d=>setAuditRows(d)).catch(()=>{ setApiError(true); setAuditRows([]) })
    fetchJSON<ApiApprovalPolicy>('/admin/approval-policy').then(d=>setPolicy(d)).catch(()=>{ setApiError(true); setPolicy(null) })
  }
  useEffect(()=>{ loadAll() },[])
  const doLogin=async()=>{
    if(!loginForm.admin_id){ setLoginError('Pick an admin'); return }
    setLoggingIn(true); setLoginError(null)
    try{
      const res=await fetch(`${API_BASE}/admin/login`,{ method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ admin_id:Number(loginForm.admin_id), password:loginForm.password }) })
      const data=await res.json()
      if(!res.ok){ setLoginError(data.detail || 'Login failed'); return }
      setCurrentAdmin(data); persistCurrentAdmin(data); setLoginForm({admin_id:'',password:''}); loadAll()
    }catch{ setLoginError(`Can't reach the backend at ${API_BASE}.`) }
    finally{ setLoggingIn(false) }
  }
  const doCreate=async()=>{
    if(!createForm.name.trim() || !createForm.company_id.trim() || !createForm.password){ setCreateError('Name, company ID and password are required'); return }
    setCreating(true); setCreateError(null)
    try{
      const res=await fetch(`${API_BASE}/admin/create`,{ method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ name:createForm.name.trim(), company_id:createForm.company_id.trim(), role:createForm.role.trim()||null, password:createForm.password }) })
      const data=await res.json()
      if(!res.ok){ setCreateError(data.detail || 'Could not create admin'); return }
      setCurrentAdmin(data); persistCurrentAdmin(data); setCreateForm({name:'',company_id:'',role:'',password:''}); loadAll()
    }catch{ setCreateError(`Can't reach the backend at ${API_BASE}.`) }
    finally{ setCreating(false) }
  }
  const doLogout=async()=>{
    if(!currentAdmin) return
    setLoggingOut(true)
    try{ await fetch(`${API_BASE}/admin/logout`,{ method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ admin_id:currentAdmin.id }) }) }
    catch{ /* still clear locally even if the backend call fails -- don't strand the UI signed-in-looking against a dead backend */ }
    setCurrentAdmin(null); persistCurrentAdmin(null); loadAll(); setLoggingOut(false)
  }
  const setPolicyMode=async(scope:'severity'|'playbook',key:string,mode:'auto'|'manual')=>{
    setPolicy(p=>p ? { ...p, [scope]: { ...p[scope], [key]: mode } } : p)
    try{ await fetch(`${API_BASE}/admin/approval-policy`,{ method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ scope, key, mode, updated_by: currentAdmin?.name || null }) }) }
    catch{ /* leave the optimistic value in place -- next load will reconcile it if the call actually failed */ }
  }
  const sessionRows=(sessions ?? []).map(s=>[s.admin_name, s.company_id, s.role||'—', toLocalDateTime(s.login_at), s.logout_at?toLocalDateTime(s.logout_at):'Active'])
  const downloadRows=(auditRows ?? []).filter(r=>r.action==='Report downloaded').map(r=>[toLocalDateTime(r.timestamp), r.actor, r.target, r.result])
  return <>
    <div className="page-title"><div><div className="eyebrow">SYSTEM / ACCESS CONTROL</div><h1>Admin Panel</h1></div></div>
    <ApiNotice show={apiError}/>
    <div className="admin-grid">
      <Panel title="Signed in as">
        {currentAdmin
          ? <div className="admin-current"><div className="admin-current-row"><UserRound size={22}/><div><strong>{currentAdmin.name}</strong><span>{currentAdmin.role || 'Admin'} · Company ID {currentAdmin.company_id}</span></div></div><button className="outline-btn" onClick={doLogout} disabled={loggingOut}>{loggingOut?'Logging out…':'Log out'}</button></div>
          : <p className="muted">No admin signed in — actions are attributed to "analyst" until someone logs in or is created.</p>}
      </Panel>
      <Panel title="Log in as existing admin">
        <div className="form-stack">
          <label>Admin<select value={loginForm.admin_id} onChange={e=>setLoginForm(f=>({...f,admin_id:e.target.value}))}><option value="">Select…</option>{(admins ?? []).map(a=><option key={a.id} value={a.id}>{a.name} ({a.company_id})</option>)}</select></label>
          <label>Password<input type="password" value={loginForm.password} onChange={e=>setLoginForm(f=>({...f,password:e.target.value}))}/></label>
          {loginError && <p className="muted" style={{color:COLORS.critical}}>{loginError}</p>}
          <button className="primary-btn" onClick={doLogin} disabled={loggingIn}><LockKeyhole size={14}/> {loggingIn?'Logging in…':'Log in'}</button>
        </div>
      </Panel>
      <Panel title="Create new admin">
        <div className="form-stack">
          <label>Name<input value={createForm.name} onChange={e=>setCreateForm(f=>({...f,name:e.target.value}))}/></label>
          <label>Company ID<input value={createForm.company_id} onChange={e=>setCreateForm(f=>({...f,company_id:e.target.value}))}/></label>
          <label>Role<input value={createForm.role} onChange={e=>setCreateForm(f=>({...f,role:e.target.value}))} placeholder="(optional)"/></label>
          <label>Password<input type="password" value={createForm.password} onChange={e=>setCreateForm(f=>({...f,password:e.target.value}))}/></label>
          {createError && <p className="muted" style={{color:COLORS.critical}}>{createError}</p>}
          <button className="primary-btn" onClick={doCreate} disabled={creating}><UserRound size={14}/> {creating?'Creating…':'Create & log in'}</button>
        </div>
      </Panel>
    </div>
    <Panel title="Approval policy" className="admin-policy-panel">
      <p className="muted" style={{margin:'0 0 12px'}}>Auto/Manual per severity and per playbook — saved as a preference only for now; the response engine doesn't read this yet, so it doesn't change what actually happens to a real incoming alert.</p>
      <div className="policy-section"><h3>By severity</h3><div className="policy-grid">{Object.entries(policy?.severity ?? {}).map(([sev,mode])=><div className="policy-row" key={sev}><span>{sev}</span><div className="theme-options"><button className={mode==='auto'?'selected':''} onClick={()=>setPolicyMode('severity',sev,'auto')}>Auto</button><button className={mode==='manual'?'selected':''} onClick={()=>setPolicyMode('severity',sev,'manual')}>Manual</button></div></div>)}</div></div>
      <div className="policy-section"><h3>By playbook</h3><div className="policy-grid">{Object.entries(policy?.playbook ?? {}).map(([pb,mode])=><div className="policy-row" key={pb}><span>{pb}</span><div className="theme-options"><button className={mode==='auto'?'selected':''} onClick={()=>setPolicyMode('playbook',pb,'auto')}>Auto</button><button className={mode==='manual'?'selected':''} onClick={()=>setPolicyMode('playbook',pb,'manual')}>Manual</button></div></div>)}</div></div>
    </Panel>
    <SimpleTable title="Admin access log" headers={['ADMIN','COMPANY ID','ROLE','LOGGED IN','LOGGED OUT']} rows={sessionRows} colWidths={['150px','130px','120px','170px','170px']} statusCol={-1}/>
    <SimpleTable title="Report downloads" headers={['TIMESTAMP','DOWNLOADED BY','FILE','RESULT']} rows={downloadRows} colWidths={['150px','150px',undefined,'110px']} statusCol={-1}/>
  </>
}
function WorkspacePage({title,light,setLight,currentAdmin,setCurrentAdmin}:{title:string;light:boolean;setLight:(value:boolean)=>void;currentAdmin:AdminInfo|null;setCurrentAdmin:(a:AdminInfo|null)=>void}){const pages:Record<string,React.ReactNode>={Incidents:<Incidents/>,Investigations:<Investigations/>,Playbooks:<Playbooks/>,Runbook:<Runbook/>, 'Threat Intelligence':<ThreatIntel/>, 'Global Threat Map':<ThreatMap/>,Assets:<Assets/>, 'Response Center':<ResponseCenter/>, 'SSH / Sessions':<SshSessions/>,Audit:<Audit/>,Reports:<Reports/>, '24-Hour Report':<DailyReport/>, 'Detection Rules':<DetectionRules/>,Integrations:<Integrations/>, 'Admin Panel':<AdminPanel currentAdmin={currentAdmin} setCurrentAdmin={setCurrentAdmin}/>,Settings:<SettingsPage light={light} setLight={setLight}/>};return pages[title] || null}

export default function Page() { const [collapsed,setCollapsed]=useState(false); const [active,setActive]=useState('Overview'); const [selected,setSelected]=useState<Alert|null>(null); const [search,setSearch]=useState(''); const [light,setLight]=useState(false); const [scrolling,setScrolling]=useState(false); const [refreshKey,setRefreshKey]=useState(0); const [actionBusy,setActionBusy]=useState(false); const [actionError,setActionError]=useState<string|null>(null); const [alertCount,setAlertCount]=useState<number|null>(null); const [incidentCount,setIncidentCount]=useState<number|null>(null); const [pendingCount,setPendingCount]=useState<number|null>(null);
  // Signed-in admin (Admin Panel tab). Starts null on first render (same
  // hydration-safety reason as the timezone/landing-tab defaults below --
  // localStorage isn't read until after mount) and is loaded in the same
  // prefs effect. Kept here, not local to AdminPanel, because the
  // sidebar's bottom-left label needs it too.
  const [currentAdmin,setCurrentAdminState]=useState<AdminInfo|null>(null)
  const setCurrentAdmin=(a:AdminInfo|null)=>{ setCurrentAdminState(a) }
  const scrollTimer=useRef<ReturnType<typeof setTimeout>|null>(null); const handleScroll=()=>{setScrolling(true);if(scrollTimer.current) clearTimeout(scrollTimer.current);scrollTimer.current=setTimeout(()=>setScrolling(false),700)}; const activeNav=nav.find(([,label])=>label===active); const ActiveIcon=activeNav?.[2] || LayoutDashboard;
  // Sidebar/bell badges used to be hardcoded literals ("07", "03", "3")
  // that never matched real data. Pull real counts instead: open alerts
  // for the Alerts badge, open incidents for the Incidents badge, and
  // alerts still awaiting analyst approval for the bell. Refetches on
  // refreshKey so approve/reject actions update the badges immediately.
  useEffect(()=>{
    let cancelled=false
    api.getAlerts().then(d=>{ if(cancelled) return; setAlertCount(d.length); setPendingCount(d.filter(a=>(a.response_status||'pending_approval')==='pending_approval').length) }).catch(()=>{ if(!cancelled){ setAlertCount(null); setPendingCount(null) } })
    api.getIncidents().then(d=>{ if(!cancelled) setIncidentCount(d.length) }).catch(()=>{ if(!cancelled) setIncidentCount(null) })
    return ()=>{ cancelled=true }
  },[refreshKey])
  // Load saved Settings preferences once on mount. Both default to a fixed
  // value on first render (Overview / local time) so server-rendered and
  // client-hydrated markup match -- reading localStorage here, after
  // mount, rather than in useState's initializer, is what avoids a
  // hydration mismatch if a saved preference differs from the default.
  useEffect(()=>{
    try{
      const savedTz = localStorage.getItem(TIMEZONE_PREF_KEY)
      if(savedTz==='utc'||savedTz==='local') setDisplayTimezone(savedTz)
    }catch{ /* ignore */ }
    try{
      const savedTab = localStorage.getItem(DEFAULT_TAB_KEY)
      if(savedTab && nav.some(([,label])=>label===savedTab)) setActive(savedTab)
    }catch{ /* ignore */ }
    const savedAdmin = loadCurrentAdmin()
    if(savedAdmin) setCurrentAdminState(savedAdmin)
  },[])
  // On success: reflect the new status on the selected alert immediately
  // (so the drawer updates even before the list refetch lands) and bump
  // refreshKey so Overview/DataTable -- which each fetched /alerts once on
  // mount -- refetch and pick up the change. On failure: surface it in the
  // drawer instead of silently doing nothing, which is what made
  // Approve/Reject look broken.
  const handleApprove=async(a:Alert)=>{
    setActionBusy(true); setActionError(null)
    try{ await api.approveAlert(a.rawId); setSelected({...a, status:'approved_and_executed'}); setRefreshKey(k=>k+1) }
    catch(err){ setActionError(err instanceof Error ? err.message : 'Failed to approve this response.') }
    finally{ setActionBusy(false) }
  }
  const handleReject=async(a:Alert)=>{
    setActionBusy(true); setActionError(null)
    try{ await api.rejectAlert(a.rawId); setSelected({...a, status:'rejected'}); setRefreshKey(k=>k+1) }
    catch(err){ setActionError(err instanceof Error ? err.message : 'Failed to reject this response.') }
    finally{ setActionBusy(false) }
  }
  const renderPage = active==='Overview' ? <Overview onSelect={setSelected} refreshKey={refreshKey} onNavigate={setActive} bumpRefresh={()=>setRefreshKey(k=>k+1)}/> : active==='Alerts' ? <DataTable onSelect={setSelected} refreshKey={refreshKey}/> : <WorkspacePage title={active} light={light} setLight={setLight} currentAdmin={currentAdmin} setCurrentAdmin={setCurrentAdmin}/>; return <div className={`soc-app ${light?'light':''}`}><aside className={`sidebar ${collapsed?'collapsed':''}`}><div className="brand"><Shield size={18}/><span>SOAR PLATFORM</span></div><button className="collapse-btn" onClick={()=>setCollapsed(!collapsed)}>{collapsed?<ChevronRight size={15}/>:<ChevronLeft size={15}/>}</button><div className="nav-groups">{['COMMAND','MONITOR','AUTOMATE','INTELLIGENCE','OPERATIONS','SYSTEM'].map(group=><div className="nav-group" key={group}><span className="group-label">{group}</span>{nav.filter(n=>n[0]===group).map(([,label,Icon])=><button className={`nav-item ${active===label?'active':''}`} onClick={()=>setActive(label as string)} key={label} title={collapsed?label:undefined}><Icon size={16}/><span>{label}</span>{label==='Alerts'&&!!alertCount&&<b className="nav-badge">{alertCount}</b>}{label==='Incidents'&&!!incidentCount&&<b className="nav-badge red">{incidentCount}</b>}</button>)}</div>)}</div><div className="sidebar-foot"><div className="user-avatar"><UserRound size={15}/></div><span>{currentAdmin?.name || 'SOC'}</span><MoreIcon/></div></aside><main className="main"><header className="topbar"><div className="global-search"><Search size={16}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search IP, domain, hash, alert or incident..."/><kbd><Command size={11}/>K</kbd></div><div className="top-actions"><span className="live"><i/> LIVE</span><button className="top-icon"><Bell size={17}/>{!!pendingCount&&<b>{pendingCount}</b>}</button><button className="top-icon"><Activity size={17}/></button><button className="avatar">SOC</button></div></header><div className={`content ${scrolling?'is-scrolling':''}`} key={active} onScroll={handleScroll}>{renderPage}</div></main>{selected&&<Drawer alert={selected} close={()=>{setSelected(null); setActionError(null)}} onApprove={handleApprove} onReject={handleReject} busy={actionBusy} error={actionError}/>}</div> }
function MoreIcon(){return <span className="more-icon">•••</span>}

// API wiring. Every one of these hits a real backend/main.py endpoint.
// approveAlert/rejectAlert are called from Page(); the components that
// need lookup/geo/ssh (Investigations, ThreatMap, SshSessions) call
// fetchJSON()/fetch() directly with their own loading/error state instead
// of going through this object, so lookupIOC/getGeoThreatData/connectSsh
// below are equivalent, reusable versions of those same calls for
// anything else that wants them.
export const api = {
  approveAlert: async (id:number) => { const r = await fetch(`${API_BASE}/alerts/${id}/approve`, {method:'POST'}); if(!r.ok) throw new Error(`approve ${id} -> ${r.status}`); return r.json() },
  // Overview's "Create incident" modal calls this -- same POST /alerts
  // pipeline every automated detection uses, just hand-submitted instead of
  // coming from a watcher.
  createAlert: async (payload:{source:string; description:string; ip:string|null; timestamp:string}) => { const r = await fetch(`${API_BASE}/alerts`, {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(payload)}); if(!r.ok) throw new Error(`create alert -> ${r.status}`); return r.json() },
  rejectAlert: async (id:number) => { const r = await fetch(`${API_BASE}/alerts/${id}/reject`, {method:'POST'}); if(!r.ok) throw new Error(`reject ${id} -> ${r.status}`); return r.json() },
  getAlerts: async () => fetchJSON<ApiAlert[]>('/alerts'),
  getIncidents: async () => fetchJSON<ApiIncident[]>('/incidents'),
  getReports: async () => fetchJSON<ApiReport[]>('/reports'),
  getDailyReports: async () => fetchJSON<ApiReport[]>('/reports/daily'),
  lookupIOC: async (type:string,value:string) => fetch(`${API_BASE}/threat-intel/lookup?type=${type}&value=${encodeURIComponent(value)}`),
  getGeoThreatData: async () => fetch(`${API_BASE}/threat-intel/geo`),
  connectSsh: async (payload:Record<string,string>) => fetch(`${API_BASE}/ssh/connect`, {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(payload)}),
  getSshSessions: async () => fetchJSON<ApiSshSession[]>('/ssh/sessions'),
  getDetectionRules: async () => fetchJSON<ApiDetectionRule[]>('/detection-rules'),
  toggleDetectionRule: async (key:string) => fetch(`${API_BASE}/detection-rules/${key}/toggle`, {method:'POST'}),
}
