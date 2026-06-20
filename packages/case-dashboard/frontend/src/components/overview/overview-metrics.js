// ─────────────────────────────────────────────────────────────────────────
// Overview — pure metric derivations (no JSX, no store). All KPI / chart /
// feed data is derived from the SAME polled store slices the old OverviewTab
// read (summary, findings, delta) — no new store keys (the useStore.interface
// contract is frozen). Unit-tested directly.
// ─────────────────────────────────────────────────────────────────────────

import { CONF_ORDER, confClass, findingTs, normStatus } from '@/components/findings/findings-utils'

/**
 * KPI counts. Prefer the server `summary.findings.by_status` (DB authority),
 * falling back to client-side counts when the summary hasn't loaded yet.
 */
export function deriveKpis(summary, findings, delta) {
  const list = findings ?? []
  const fstats = summary?.findings ?? {}
  const byStatus = fstats.by_status ?? {}
  const countStatus = (s) => list.filter((f) => normStatus(f) === s).length

  const total = fstats.total ?? list.length
  const approved = byStatus.approved ?? byStatus.APPROVED ?? countStatus('approved')
  const pending = byStatus.draft ?? byStatus.DRAFT ?? countStatus('draft')
  const staged = (delta ?? []).length
  const reviewPct = list.length > 0 ? Math.round((staged / list.length) * 100) : 0
  return { total, approved, pending, staged, reviewPct }
}

/**
 * Severity (confidence) distribution → ordered rows with token classes + pct.
 * Each row also carries `awaiting` (count of that severity still in draft/review)
 * and `recent` (count whose activity timestamp is within the last 24h) so the
 * widget can show an interactive "N awaiting review" callout + a 24h delta
 * without a second pass. `total` is the grand total (for the share-of-total pct).
 */
export function severityCounts(findings, now = Date.now()) {
  // Only the three canonical tiers (P0 model-shift: SPECULATIVE dropped from UI).
  // Historical SPECULATIVE findings are folded into LOW so their counts aren't lost.
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 }
  const awaiting = { HIGH: 0, MEDIUM: 0, LOW: 0 }
  const recent = { HIGH: 0, MEDIUM: 0, LOW: 0 }
  const DAY = 24 * 3600 * 1000
  for (const f of findings ?? []) {
    const raw = (f.confidence ?? '').toUpperCase()
    // Map SPECULATIVE → LOW for display (backward compat with existing data).
    const c = (raw === 'SPECULATIVE' ? 'LOW' : raw)
    if (!(c in counts)) continue
    counts[c] += 1
    if (normStatus(f) === 'draft') awaiting[c] += 1
    const ts = findingTs(f)
    if (ts && now - new Date(ts).getTime() < DAY) recent[c] += 1
  }
  const max = Math.max(1, ...Object.values(counts))
  const total = Object.values(counts).reduce((s, n) => s + n, 0)
  return CONF_ORDER.map((key) => {
    const cls = confClass(key)
    return {
      key,
      label: cls.label,
      count: counts[key],
      awaiting: awaiting[key],
      recent: recent[key],
      pct: Math.round((counts[key] / max) * 100),
      sharePct: total > 0 ? Math.round((counts[key] / total) * 100) : 0,
      total,
      cls,
    }
  })
}

/** Distinct MITRE ATT&CK technique ids across all findings, sorted. */
export function mitreTechniques(findings) {
  const ids = new Set()
  for (const f of findings ?? []) for (const id of f.mitre_ids ?? []) ids.add(id)
  return [...ids].sort()
}

// ── MITRE ATT&CK tactic model (RUN-4c) ───────────────────────────────────────
// Technique → tactic catalog + per-tactic token-class bundle so the panel reads
// "Lateral Movement › T1021.001" (grouped headers + colour-coded chips), not a
// flat pill list. Colour is supplementary to the always-present tactic LABEL and
// mono T-code (colour-not-only). Token classes are STATIC literals (JIT) — never
// orange (reserved for the agent). Unknown ids fall back to the `other` tactic.

/** Kill-chain order for stable tactic grouping. */
export const TACTIC_ORDER = [
  'initial-access', 'execution', 'persistence', 'privilege-escalation',
  'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
  'collection', 'command-and-control', 'exfiltration', 'impact', 'other',
]

/** tactic → label + static token-class bundle (text / dot / tint / ring). */
export const TACTIC_CLASS = {
  'initial-access': { label: 'Initial Access', text: 'text-sev-med', dot: 'bg-sev-med', tint: 'bg-sev-med/10', ring: 'border-sev-med/40' },
  'execution': { label: 'Execution', text: 'text-sev-low', dot: 'bg-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/40' },
  'persistence': { label: 'Persistence', text: 'text-sev-spec', dot: 'bg-sev-spec', tint: 'bg-sev-spec/10', ring: 'border-sev-spec/40' },
  'privilege-escalation': { label: 'Privilege Escalation', text: 'text-sev-high', dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  'defense-evasion': { label: 'Defense Evasion', text: 'text-status-staged', dot: 'bg-status-staged', tint: 'bg-status-staged/10', ring: 'border-status-staged/40' },
  'credential-access': { label: 'Credential Access', text: 'text-sev-high', dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  'discovery': { label: 'Discovery', text: 'text-sev-low', dot: 'bg-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/40' },
  'lateral-movement': { label: 'Lateral Movement', text: 'text-sev-med', dot: 'bg-sev-med', tint: 'bg-sev-med/10', ring: 'border-sev-med/40' },
  'collection': { label: 'Collection', text: 'text-status-approved', dot: 'bg-status-approved', tint: 'bg-status-approved/10', ring: 'border-status-approved/40' },
  'command-and-control': { label: 'Command and Control', text: 'text-sev-high', dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  'exfiltration': { label: 'Exfiltration', text: 'text-sev-high', dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  'impact': { label: 'Impact', text: 'text-destructive', dot: 'bg-destructive', tint: 'bg-destructive/10', ring: 'border-destructive/40' },
  'other': { label: 'Other', text: 'text-muted-foreground', dot: 'bg-muted-foreground', tint: 'bg-secondary', ring: 'border-border' },
}

export function tacticMeta(tactic) {
  return TACTIC_CLASS[tactic] ?? TACTIC_CLASS.other
}

/** Curated technique → { name, tactic } catalog (the mock's technique→tactic data). */
export const MITRE_CATALOG = {
  'T1021': { name: 'Remote Services', tactic: 'lateral-movement' },
  'T1021.001': { name: 'Remote Services: RDP', tactic: 'lateral-movement' },
  'T1078': { name: 'Valid Accounts', tactic: 'privilege-escalation' },
  'T1078.002': { name: 'Valid Accounts: Domain Accounts', tactic: 'privilege-escalation' },
  'T1053': { name: 'Scheduled Task/Job', tactic: 'persistence' },
  'T1053.005': { name: 'Scheduled Task', tactic: 'persistence' },
  'T1574': { name: 'Hijack Execution Flow', tactic: 'defense-evasion' },
  'T1574.002': { name: 'DLL Side-Loading', tactic: 'defense-evasion' },
  'T1039': { name: 'Data from Network Shared Drive', tactic: 'collection' },
  'T1530': { name: 'Data from Cloud Storage', tactic: 'collection' },
  'T1071': { name: 'Application Layer Protocol', tactic: 'command-and-control' },
  'T1071.001': { name: 'Web Protocols', tactic: 'command-and-control' },
  'T1070': { name: 'Indicator Removal', tactic: 'defense-evasion' },
  'T1070.001': { name: 'Clear Windows Event Logs', tactic: 'defense-evasion' },
  'T1059': { name: 'Command and Scripting Interpreter', tactic: 'execution' },
  'T1059.001': { name: 'PowerShell', tactic: 'execution' },
  'T1486': { name: 'Data Encrypted for Impact', tactic: 'impact' },
  'T1003': { name: 'OS Credential Dumping', tactic: 'credential-access' },
}

/** Resolve a technique id → { id, name, tactic } (sub-technique falls back to base). */
export function techniqueMeta(id) {
  const hit = MITRE_CATALOG[id] ?? MITRE_CATALOG[String(id).split('.')[0]]
  return { id, name: hit?.name ?? null, tactic: hit?.tactic ?? 'other' }
}

/**
 * mitreByTactic — distinct techniques across findings, grouped under their ATT&CK
 * tactic in kill-chain order. Each technique records the finding ids that cite it
 * (for the detail side-panel). Returns `[{ tactic, meta, techniques:[{ id, name,
 * findingIds }] }]`, empty tactics omitted.
 */
export function mitreByTactic(findings) {
  const byId = new Map()
  for (const f of findings ?? []) {
    for (const id of f.mitre_ids ?? []) {
      if (!byId.has(id)) byId.set(id, { ...techniqueMeta(id), findingIds: [] })
      byId.get(id).findingIds.push(f.id)
    }
  }
  const groups = new Map()
  for (const t of byId.values()) {
    if (!groups.has(t.tactic)) groups.set(t.tactic, [])
    groups.get(t.tactic).push(t)
  }
  return TACTIC_ORDER.filter((tac) => groups.has(tac)).map((tactic) => ({
    tactic,
    meta: tacticMeta(tactic),
    techniques: groups.get(tactic).sort((a, b) => a.id.localeCompare(b.id)),
  }))
}

/** Velocity ranges (the chart's 7d / 24h / all toggle). */
export const VELOCITY_RANGES = [
  { key: '24h', label: '24h', ms: 24 * 3600 * 1000, buckets: 24, step: 3600 * 1000 },
  { key: '7d', label: '7d', ms: 7 * 24 * 3600 * 1000, buckets: 7, step: 24 * 3600 * 1000 },
  { key: 'all', label: 'All', ms: Infinity, buckets: 12, step: null },
]

function fmtBucket(date, rangeKey) {
  if (rangeKey === '24h') return `${String(date.getHours()).padStart(2, '0')}:00`
  return `${date.getMonth() + 1}/${date.getDate()}`
}

/**
 * velocitySeries — per-bucket count of findings created/modified in each time
 * slot, for the area chart. For '24h'/'7d' the buckets are fixed-width ending
 * "now"; for 'all' the span between the earliest and latest finding is divided
 * into `buckets` equal slots. Returns `[{ t, label, count }]`, oldest → newest.
 */
export function velocitySeries(findings, rangeKey, now = Date.now()) {
  const range = VELOCITY_RANGES.find((r) => r.key === rangeKey) ?? VELOCITY_RANGES[0]
  const stamped = (findings ?? [])
    .map((f) => {
      const ts = findingTs(f)
      return ts ? new Date(ts).getTime() : null
    })
    .filter((t) => t !== null && !Number.isNaN(t))

  if (rangeKey === 'all') {
    if (stamped.length === 0) return []
    const min = Math.min(...stamped)
    const max = Math.max(...stamped, now)
    const span = Math.max(1, max - min)
    const step = span / range.buckets
    const series = Array.from({ length: range.buckets }, (_, i) => {
      const start = min + i * step
      return { t: start, label: fmtBucket(new Date(start), 'all'), count: 0 }
    })
    for (const t of stamped) {
      const idx = Math.min(range.buckets - 1, Math.floor((t - min) / step))
      series[idx].count += 1
    }
    return series
  }

  const start = now - range.ms
  const series = Array.from({ length: range.buckets }, (_, i) => {
    const slotStart = start + i * range.step
    return { t: slotStart, label: fmtBucket(new Date(slotStart), rangeKey), count: 0 }
  })
  for (const t of stamped) {
    if (t < start || t > now) continue
    const idx = Math.min(range.buckets - 1, Math.floor((t - start) / range.step))
    series[idx].count += 1
  }
  return series
}

/** Activity-feed ranges (independent of the velocity toggle). */
export const ACTIVITY_RANGES = [
  { key: '24h', label: 'Last 24h', ms: 24 * 3600 * 1000 },
  { key: '7d', label: 'Last 7d', ms: 7 * 24 * 3600 * 1000 },
  { key: 'all', label: 'All', ms: Infinity },
]

/** Most-recent findings within the window, newest first, capped at `limit`. */
export function recentActivity(findings, rangeKey, limit = 8, now = Date.now()) {
  const range = ACTIVITY_RANGES.find((r) => r.key === rangeKey) ?? ACTIVITY_RANGES[0]
  return (findings ?? [])
    .filter((f) => {
      if (range.ms === Infinity) return true
      const ts = findingTs(f)
      return ts ? now - new Date(ts).getTime() < range.ms : false
    })
    .slice()
    .sort((a, b) => new Date(findingTs(b) ?? 0) - new Date(findingTs(a) ?? 0))
    .slice(0, limit)
}
