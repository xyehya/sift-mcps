// ─────────────────────────────────────────────────────────────────────────
// Findings — pure helpers + token-class maps (no JSX, no store). Kept in a
// .js module so the component files stay clean under react-refresh's
// only-export-components rule, and so the filter/delta logic is unit-testable
// in isolation. Ported from the old FindingsTab monolith (behavior preserved,
// store/api delta contract unchanged), restyled to Graphite Emerald tokens.
//
// IMPORTANT: every Tailwind class below is a STATIC literal so the JIT emits it.
// Never build a token class by interpolation (`text-${x}`) — it won't generate.
// ─────────────────────────────────────────────────────────────────────────

/**
 * Confidence == the forensic severity dimension. Order = high → low.
 * "Speculative" was dropped in P0 model-shift (handoff §3: High/Med/Low only).
 * The SPECULATIVE fallback entry is kept in CONF_CLASS for backward compat with
 * any existing data that carries the label — it renders with the low-steel tone.
 */
export const CONF_ORDER = ['HIGH', 'MEDIUM', 'LOW']

/** Static token classes per confidence (→ --sev-* tokens). */
export const CONF_CLASS = {
  HIGH: { label: 'High', text: 'text-sev-high', bg: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  MEDIUM: { label: 'Medium', text: 'text-sev-med', bg: 'bg-sev-med', tint: 'bg-sev-med/10', ring: 'border-sev-med/40' },
  LOW: { label: 'Low', text: 'text-sev-low', bg: 'bg-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/40' },
  // Backward-compat fallback — renders as Low/steel so the UI doesn't break on
  // historical data; the examiner edit select no longer exposes this tier.
  SPECULATIVE: { label: 'Speculative', text: 'text-sev-low', bg: 'bg-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/40' },
}

/** Resolve the class bundle for a finding's confidence (null when unknown). */
export function confClass(confidence) {
  return CONF_CLASS[(confidence ?? '').toUpperCase()] ?? null
}

/**
 * Display label for a finding's CATEGORICAL confidence (e.g. 'High'), or null.
 * The model emits High/Medium/Low; the UI shows this text — never a numeric %
 * derived from CONF_SCORE, which fabricates precision the model never reported
 * (operator decision, P35-11). The numeric helpers below stay for the (unused)
 * graded ring and remain pure, but no finding badge renders a % anymore.
 */
export function confidenceLabel(confidence) {
  return confClass(confidence)?.label ?? null
}

/**
 * Representative numeric score per categorical confidence, used by the graded
 * confidence ring when a finding carries no explicit `confidence_score`. The
 * categorical label stays the source of truth; the score only grades the ring.
 * SPECULATIVE kept for backward compat (maps to the crimson range, score 30).
 */
export const CONF_SCORE = { HIGH: 92, MEDIUM: 74, LOW: 48, SPECULATIVE: 30 }

/** Numeric 0–100 confidence for a finding (explicit score wins, else mapped). */
export function confidenceScore(finding) {
  const explicit = finding?.confidence_score ?? finding?.confidenceScore
  if (Number.isFinite(explicit)) return Math.max(0, Math.min(100, explicit))
  return CONF_SCORE[(finding?.confidence ?? '').toUpperCase()] ?? null
}

/**
 * Graded confidence ring (DESIGN-SYSTEM.md): ≥85 jade · ≥65 amber · else
 * crimson — graded, NOT branded by category. Returns static token classes
 * (`text` for labels, `dot` for swatches) + the matching CSS-var token for the
 * SVG stroke (data-driven, no raw hex). All class strings are literal so the
 * JIT emits them (§5).
 */
export const RING_GRADE = {
  jade: { text: 'text-status-approved', dot: 'bg-status-approved', stroke: 'var(--status-approved)' },
  amber: { text: 'text-sev-med', dot: 'bg-sev-med', stroke: 'var(--sev-med)' },
  crimson: { text: 'text-sev-high', dot: 'bg-sev-high', stroke: 'var(--sev-high)' },
}
export function confidenceGrade(score) {
  if (score == null) return null
  if (score >= 85) return RING_GRADE.jade
  if (score >= 65) return RING_GRADE.amber
  return RING_GRADE.crimson
}

/** Status → static token classes + label. `draft` is surfaced as "Pending". */
export const STATUS_CLASS = {
  approved: { label: 'Approved', text: 'text-status-approved', dot: 'bg-status-approved', ring: 'border-status-approved/40' },
  draft: { label: 'Pending', text: 'text-status-pending', dot: 'bg-status-pending', ring: 'border-status-pending/40' },
  rejected: { label: 'Rejected', text: 'text-status-rejected', dot: 'bg-status-rejected', ring: 'border-status-rejected/40' },
}

/** Status filter chips used by the list. */
export const FILTERS = ['pending', 'approved', 'rejected', 'all']

export function normStatus(f) {
  return (f?.status ?? '').toLowerCase()
}

export function statusMeta(status) {
  return STATUS_CLASS[(status ?? '').toLowerCase()] ?? { label: status || 'Unknown', text: 'text-muted-foreground', dot: 'bg-muted-foreground', ring: 'border-border' }
}

/** A delta/tag value may be a plain string or `{ value }` object. */
export function getTagString(t) {
  if (typeof t === 'object' && t !== null) return t.value ?? JSON.stringify(t)
  return String(t)
}

/** Best available activity timestamp for a finding. */
export function findingTs(f) {
  return f?.modified_at || f?.event_timestamp || f?.timestamp || null
}

/** Account value(s) for a finding, normalised to a string[] for matching. */
function accountValues(f) {
  const raw = f?.affected_account || f?.account
  if (!raw) return []
  if (Array.isArray(raw)) return raw.map((a) => (typeof a === 'string' ? a : a?.value ?? ''))
  if (typeof raw === 'string') return raw.split(',').map((s) => s.trim()).filter(Boolean)
  return []
}

/**
 * filterFindings — status + host + account + confidence + free-text search,
 * ported verbatim from the old monolith (console.log debug lines removed).
 * `account` of '' means the explicit "no account" filter; null means "no account
 * filter". `confidence` (e.g. 'HIGH') is the orthogonal severity filter carried
 * via the hash (RUN-4c); null means "no confidence filter".
 */
export function filterFindings(findings, { filter = 'pending', host = null, account = null, confidence = null, search = '' } = {}) {
  let list = findings ?? []
  if (filter === 'pending') list = list.filter((f) => normStatus(f) === 'draft')
  else if (filter === 'approved') list = list.filter((f) => normStatus(f) === 'approved')
  else if (filter === 'rejected') list = list.filter((f) => normStatus(f) === 'rejected')

  if (confidence) {
    const want = String(confidence).toUpperCase()
    list = list.filter((f) => (f.confidence ?? '').toUpperCase() === want)
  }
  if (host) {
    const h = host.toUpperCase()
    list = list.filter((f) => (f.host ?? '').toUpperCase() === h)
  }
  if (account !== null) {
    if (account === '') list = list.filter((f) => accountValues(f).length === 0)
    else list = list.filter((f) => accountValues(f).includes(account))
  }
  if (search) {
    const q = search.toLowerCase()
    list = list.filter((f) => (f.id ?? '').toLowerCase().includes(q) || (f.title ?? '').toLowerCase().includes(q))
  }
  return list
}

/** pending (draft) vs reviewed counts across all findings. */
export function reviewCounts(findings) {
  let pending = 0
  for (const f of findings ?? []) if (normStatus(f) === 'draft') pending += 1
  return { pending, reviewed: (findings?.length ?? 0) - pending }
}

/**
 * Build a fresh delta item for an approve/reject. The /api/delta POST replaces
 * the WHOLE delta document, so callers send `[...others, this]`.
 */
export function buildStageItem(finding, action, note = '') {
  return {
    id: finding.id,
    type: finding.type ?? 'finding',
    action,
    content_hash_at_review: finding.content_hash ?? '',
    modifications: {},
    ...(note ? { note } : {}),
  }
}

/** Merge a single field edit into an existing (or new) delta item. */
export function buildEditItem(existing, finding, field, original, modified) {
  const base = existing || {
    id: finding.id,
    type: finding.type ?? 'finding',
    action: 'edit',
    content_hash_at_review: finding.content_hash ?? '',
    modifications: {},
  }
  return { ...base, modifications: { ...(base.modifications ?? {}), [field]: { original, modified } } }
}

/** Replace (or insert) an item for `id` in a delta array. */
export function upsertDelta(delta, item) {
  return [...(delta ?? []).filter((d) => d.id !== item.id), item]
}

/** Effective finding = base fields overlaid with staged modifications. */
export function effectiveFinding(finding, stagedItem) {
  if (!stagedItem?.modifications) return finding
  const res = { ...finding }
  for (const [k, mod] of Object.entries(stagedItem.modifications)) res[k] = mod.modified
  return res
}

/** Timeline events within ±2h of the finding (for the detail context panel). */
export function contextWindow(finding, timeline) {
  const rawTs = finding?.event_timestamp || finding?.timestamp
  if (!rawTs || !timeline?.length) return []
  const ts = new Date(rawTs).getTime()
  const TWO_H = 2 * 3600 * 1000
  return timeline
    .filter((e) => Math.abs(new Date(e.timestamp).getTime() - ts) <= TWO_H)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
}
