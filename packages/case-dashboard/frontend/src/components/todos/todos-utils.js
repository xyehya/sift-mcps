// ─────────────────────────────────────────────────────────────────────────
// TODOs — pure helpers + token-class maps (no JSX / no store) so the sort /
// filter logic is unit-testable and the component files stay clean under
// react-refresh's only-export-components rule.
//
// IMPORTANT: every Tailwind class below is a STATIC literal so the JIT emits it
// (AGENTS §3/§5). Never build a token class by interpolation. Priority colours
// map to the severity scale (High=crimson, Medium=amber, Low=steel) and status
// to jade/amber — the legacy `--cyan` accent for Low is dropped per DESIGN-SYSTEM.
// ─────────────────────────────────────────────────────────────────────────

export const PRIORITY_WEIGHT = { high: 3, medium: 2, low: 1 }

// Priority → token text-colour class (literal map; JIT-safe). Severity scale.
const PRIORITY_TEXT = {
  high: 'text-sev-high',
  medium: 'text-sev-med',
  low: 'text-sev-low',
}
// Priority → token chip classes (text + faint bg + faint border; literal map).
const PRIORITY_CHIP = {
  high: 'text-sev-high bg-crimson/10 border-crimson/30',
  medium: 'text-sev-med bg-amber/10 border-amber/30',
  low: 'text-sev-low bg-steel/10 border-steel/30',
}
// Status → token chip classes (literal map).
const STATUS_CHIP = {
  open: 'text-status-pending bg-amber/10 border-amber/30',
  completed: 'text-status-approved bg-jade/10 border-jade/30',
}

// Priority → Title-case label (matches findings-utils High/Medium/Low casing,
// rendered through an `uppercase` chip per the typography bar §A). Fixes the
// operator-flagged inconsistent first-letter casing (was raw lowercase `pri`).
const PRIORITY_LABEL = { high: 'High', medium: 'Medium', low: 'Low' }

export function priorityTextClass(priority) {
  return PRIORITY_TEXT[priority] || 'text-muted-foreground'
}
export function priorityChipClass(priority) {
  return PRIORITY_CHIP[priority] || 'text-muted-foreground bg-bg-raised border-border-soft'
}
export function priorityLabel(priority) {
  return PRIORITY_LABEL[priority] || (priority ?? '—')
}
export function statusChipClass(status) {
  return STATUS_CHIP[status] || 'text-muted-foreground bg-bg-raised border-border-soft'
}

/** Human date string — "—" for falsy/invalid input (legacy parity). */
export function formatDate(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

/**
 * Filter + sort the TODO list (legacy parity): apply the priority + status
 * filters, then sort by priority desc (high→medium→low) and created_at asc.
 * Pure — takes the list + filters, returns a new sorted array.
 */
export function sortTodos(todos, priorityFilter, statusFilter) {
  let list = [...(todos || [])]
  if (priorityFilter !== 'all') {
    list = list.filter((t) => (t.priority ?? 'medium') === priorityFilter)
  }
  if (statusFilter !== 'all') {
    list = list.filter((t) => (t.status ?? 'open') === statusFilter)
  }
  list.sort((a, b) => {
    const pa = PRIORITY_WEIGHT[a.priority] ?? 2
    const pb = PRIORITY_WEIGHT[b.priority] ?? 2
    if (pa !== pb) return pb - pa
    return (a.created_at ?? '').localeCompare(b.created_at ?? '')
  })
  return list
}

/** Parse the comma-separated related-findings input into a trimmed id list. */
export function parseRelated(related) {
  return (related ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}
