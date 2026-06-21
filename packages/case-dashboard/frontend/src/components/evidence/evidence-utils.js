// ─────────────────────────────────────────────────────────────────────────
// Evidence — pure helpers + token-class maps (no JSX, no store). Kept in a
// .js module so the component files stay clean under react-refresh's
// only-export-components rule, and so the logic is unit-testable in isolation.
//
// IMPORTANT: every Tailwind class below is a STATIC literal so the JIT emits it.
// Never build a token class by interpolation (`text-${x}`) — it won't generate.
// ─────────────────────────────────────────────────────────────────────────

/** Format an ISO timestamp for display (locale-aware, full form). */
export function formatTime(timestamp) {
  if (!timestamp) return '—'
  try {
    const date = new Date(timestamp)
    if (isNaN(date.getTime())) return String(timestamp)
    return date.toLocaleString()
  } catch {
    return String(timestamp)
  }
}

/**
 * Seal-status badge token bundle. DB authority surfaces `seal_status`; file
 * authority falls back to the manifest `status`. sealed→jade · violated→crimson
 * · else amber (pending/unknown).
 */
export function sealBadgeClass(state) {
  if (state === 'sealed') return 'text-status-approved'
  if (state === 'violated') return 'text-destructive'
  return 'text-status-pending'
}

/**
 * Sort an evidence array by a column (string or numeric), ascending/descending.
 * Pure — returns a new array.
 */
export function sortEvidence(evidence, sortCol, sortAsc) {
  return [...(evidence ?? [])].sort((a, b) => {
    const av = a[sortCol] ?? ''
    const bv = b[sortCol] ?? ''
    const cmp = typeof av === 'number' && typeof bv === 'number'
      ? av - bv
      : String(av).localeCompare(String(bv))
    return sortAsc ? cmp : -cmp
  })
}

/** Normalise a custody-violation entry (string or {path}) to a path string. */
export function violationPath(entry) {
  return typeof entry === 'string' ? entry : (entry?.path ?? '')
}

/** Truncate a sha256 to the standard display form: first 12 chars + "…". */
export function shortHash(sha256, len = 12) {
  if (!sha256) return '—'
  return `${sha256.slice(0, len)}…`
}
