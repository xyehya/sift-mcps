// ─────────────────────────────────────────────────────────────────────────
// Overview — STABLE public entry (§7/§11: imported across overview/*; this path
// must not break). Pure metric derivations (no JSX, no store). All KPI / chart /
// feed data is derived from the SAME polled store slices the old OverviewTab
// read (summary, findings, delta) — no new store keys (the useStore.interface
// contract is frozen). Unit-tested directly. The MITRE ATT&CK tactic model
// (§7 util split) lives in `overview-mitre.js` and is re-exported below so this
// remains the single import surface.
// ─────────────────────────────────────────────────────────────────────────

import { CONF_ORDER, confClass, findingTs, normStatus } from '@/components/findings/findings-utils'

export {
  mitreTechniques,
  TACTIC_ORDER,
  TACTIC_CLASS,
  tacticMeta,
  MITRE_CATALOG,
  techniqueMeta,
  mitreByTactic,
} from '@/components/overview/overview-mitre'

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
