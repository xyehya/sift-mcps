// ─────────────────────────────────────────────────────────────────────────
// Entity helpers — pure logic + static token-class maps shared by the four
// entity tabs (Timeline · Hosts · Accounts · IOCs). No JSX, no store, so the
// aggregation/sort/format logic is unit-testable and the .jsx files stay clean
// under react-refresh's only-export-components rule.
// IMPORTANT: every Tailwind class below is a STATIC literal so the JIT emits it
// — never build a token class by interpolation (`text-${x}`) (AGENTS §3 / §5).
// ─────────────────────────────────────────────────────────────────────────

/** Display form for a host string (uppercased; null/empty → UNKNOWN). */
export function displayHost(h) {
  return h ? String(h).toUpperCase() : 'UNKNOWN'
}

// ── Confidence (forensic severity dimension) ─────────────────────────────
// Severity is High/Med/Low (jade/amber/crimson/steel). The dropped
// SPECULATIVE tier folds into LOW/steel for backward compat with old data.
export const CONF_WEIGHTS = { HIGH: 4, MEDIUM: 3, LOW: 2, SPECULATIVE: 1 }

/** Static token classes per confidence (→ --sev-* tokens). JIT-safe literals. */
export const CONF_CLASS = {
  HIGH: { label: 'HIGH', text: 'text-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/30' },
  MEDIUM: { label: 'MEDIUM', text: 'text-sev-med', tint: 'bg-sev-med/10', ring: 'border-sev-med/30' },
  LOW: { label: 'LOW', text: 'text-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/30' },
  // Backward-compat: historical SPECULATIVE renders as Low/steel.
  SPECULATIVE: { label: 'LOW', text: 'text-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/30' },
}

/** Resolve the class bundle for a confidence label (muted fallback). */
export function confClass(confidence) {
  return (
    CONF_CLASS[(confidence ?? '').toUpperCase()] ?? {
      label: (confidence || 'UNKNOWN').toUpperCase(),
      text: 'text-muted-foreground',
      tint: 'bg-muted/40',
      ring: 'border-border-soft',
    }
  )
}

/**
 * Highest-weighted confidence across a list of findings (legacy parity:
 * starts at SPECULATIVE, picks the max-weight label seen). Returns the raw
 * label as it appeared in the data.
 */
export function bestConfidence(list) {
  let best = 'SPECULATIVE'
  let maxWeight = 0
  for (const f of list ?? []) {
    const conf = (f.confidence ?? '').toUpperCase()
    const weight = CONF_WEIGHTS[conf] ?? 0
    if (weight > maxWeight) {
      maxWeight = weight
      best = f.confidence
    }
  }
  return best
}

// ── Status summary ───────────────────────────────────────────────────────
// Static token classes for the draft/approved/rejected status chips.
export const STATUS_CHIP = {
  approved: { label: 'Approved', text: 'text-status-approved', tint: 'bg-status-approved/10', ring: 'border-status-approved/30' },
  draft: { label: 'Draft', text: 'text-status-pending', tint: 'bg-status-pending/10', ring: 'border-status-pending/30' },
  rejected: { label: 'Rejected', text: 'text-status-rejected', tint: 'bg-status-rejected/10', ring: 'border-status-rejected/30' },
}

/** Tally draft/approved/rejected statuses across a list (unknown → draft). */
export function statusSummary(list) {
  const out = { draft: 0, approved: 0, rejected: 0 }
  for (const f of list ?? []) {
    const st = (f.status ?? 'draft').toLowerCase()
    if (st === 'approved') out.approved += 1
    else if (st === 'rejected') out.rejected += 1
    else out.draft += 1
  }
  return out
}

// ── Account extraction (legacy parity) ───────────────────────────────────
/**
 * Accounts attributed to a finding. Accepts `affected_account` or `account`
 * as a string ("a, b"), an array of strings, or an array of `{ value }`.
 */
export function getAccountsForFinding(f) {
  const raw = f?.affected_account || f?.account
  if (!raw) return []
  if (Array.isArray(raw)) {
    return raw.map((a) => (typeof a === 'string' ? a.trim() : a?.value ?? '')).filter(Boolean)
  }
  if (typeof raw === 'string') {
    return raw.split(',').map((s) => s.trim()).filter(Boolean)
  }
  return []
}

// ── Time-range / timestamp formatting ────────────────────────────────────
/** "YYYY-MM-DD HH:MM:SS" (UTC) for a timestamp, or '—' when unparseable. */
export function fmtTs(raw) {
  if (!raw) return '—'
  const ms = new Date(raw).getTime()
  if (Number.isNaN(ms)) return '—'
  return new Date(ms).toISOString().replace('T', ' ').substring(0, 19)
}

/**
 * Min→max event-time range across a list, using event_timestamp || timestamp.
 * Collapses to a single value when min === max; '—' when none parse.
 */
export function timeRange(list) {
  let minMs = Infinity
  let maxMs = -Infinity
  let seen = false
  for (const f of list ?? []) {
    const raw = f.event_timestamp || f.timestamp
    if (!raw) continue
    const ms = new Date(raw).getTime()
    if (Number.isNaN(ms)) continue
    seen = true
    if (ms < minMs) minMs = ms
    if (ms > maxMs) maxMs = ms
  }
  if (!seen) return '—'
  const lo = fmtTs(minMs)
  const hi = fmtTs(maxMs)
  return lo === hi ? lo : `${lo} to ${hi}`
}

// ── Timeline helpers ─────────────────────────────────────────────────────
export const TIMELINE_TYPES = ['auth', 'execution', 'process', 'file', 'network', 'persistence', 'registry', 'lateral', 'other']

// Type → static text-colour token class (JIT-safe literal map). `file` maps to
// the steel token (the legacy cyan tier was dropped); cool types follow suit.
export const TIMELINE_TYPE_CLASS = {
  auth: 'text-sev-med',
  execution: 'text-sev-high',
  process: 'text-sev-high',
  file: 'text-steel',
  network: 'text-violet',
  persistence: 'text-status-approved',
  registry: 'text-muted-foreground',
  lateral: 'text-sev-high',
  other: 'text-text-ghost',
}
// Type → static bg-colour token class for the dot / active chip fill.
export const TIMELINE_TYPE_BG = {
  auth: 'bg-sev-med',
  execution: 'bg-sev-high',
  process: 'bg-sev-high',
  file: 'bg-steel',
  network: 'bg-violet',
  persistence: 'bg-status-approved',
  registry: 'bg-muted-foreground',
  lateral: 'bg-sev-high',
  other: 'bg-text-ghost',
}

/** Normalize an event's type to one of TIMELINE_TYPES ('other' when unknown). */
export function normEventType(ev) {
  const t = (ev?.event_type || ev?.type || 'other').toLowerCase()
  return TIMELINE_TYPES.includes(t) ? t : 'other'
}

/** Humanize a gap in ms → "45m" / "2h 5m" / "1d 3h". */
export function humanizeGap(gapMs) {
  const totalMinutes = Math.round(gapMs / 60000)
  if (totalMinutes < 60) return `${totalMinutes}m`
  const totalHours = Math.floor(totalMinutes / 60)
  const mins = totalMinutes % 60
  if (totalHours < 24) return mins > 0 ? `${totalHours}h ${mins}m` : `${totalHours}h`
  const days = Math.floor(totalHours / 24)
  const hours = totalHours % 24
  return hours > 0 ? `${days}d ${hours}h` : `${days}d`
}

/** Filter + chronologically sort timeline events (parity with the monolith). */
export function filterTimeline(timeline, { types = new Set(), host = 'all', search = '' } = {}) {
  let list = timeline ?? []
  if (types.size > 0) list = list.filter((e) => types.has(normEventType(e)))
  if (host !== 'all') list = list.filter((e) => e.host === host)
  if (search) {
    const q = search.toLowerCase()
    list = list.filter((e) => (e.description ?? '').toLowerCase().includes(q))
  }
  return [...list].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
}

// ── Generic table sort (Hosts / Accounts / IOCs) ─────────────────────────
/** Stable case-insensitive sort by a key extractor; toggle asc/desc. */
export function sortBy(rows, keyFn, asc = true) {
  const dir = asc ? 1 : -1
  return [...(rows ?? [])].sort((a, b) => {
    const av = keyFn(a)
    const bv = keyFn(b)
    if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * dir
    return String(av ?? '').localeCompare(String(bv ?? ''), undefined, { numeric: true }) * dir
  })
}
