// ─────────────────────────────────────────────────────────────────────────
// Evidence — pure helpers + token-class maps (no JSX, no store). Kept in a
// .js module so the component files stay clean under react-refresh's
// only-export-components rule, and so the logic is unit-testable in isolation.
//
// IMPORTANT: every Tailwind class below is a STATIC literal so the JIT emits it.
// Never build a token class by interpolation (`text-${x}`) — it won't generate.
// ─────────────────────────────────────────────────────────────────────────

/** Custody status → static token classes + label + dot. */
export const CUSTODY_CLASS = {
  sealed: {
    label: 'Sealed',
    text: 'text-status-approved',
    dot: 'bg-status-approved',
    tint: 'bg-status-approved/10',
    ring: 'border-status-approved/40',
  },
  unsealed: {
    label: 'Unsealed',
    text: 'text-destructive',
    dot: 'bg-destructive',
    tint: 'bg-destructive/10',
    ring: 'border-destructive/40',
  },
  pending: {
    label: 'Pending seal',
    text: 'text-status-pending',
    dot: 'bg-status-pending',
    tint: 'bg-status-pending/10',
    ring: 'border-status-pending/40',
  },
}

/** Resolve custody class bundle (null when unknown). */
export function custodyClass(status) {
  return CUSTODY_CLASS[(status ?? '').toLowerCase()] ?? {
    label: status || 'Unknown',
    text: 'text-muted-foreground',
    dot: 'bg-muted-foreground',
    tint: 'bg-secondary',
    ring: 'border-border',
  }
}

/** Evidence artifact type → static label + icon-key. */
export const TYPE_META = {
  disk: { label: 'Disk image', icon: 'hdd' },
  memory: { label: 'Memory dump', icon: 'cpu' },
  network: { label: 'Network capture', icon: 'wifi' },
  logs: { label: 'Log bundle', icon: 'scroll' },
  registry: { label: 'Registry / DB', icon: 'database' },
}

/** Resolve type label for an evidence item. */
export function typeMeta(type) {
  return TYPE_META[(type ?? '').toLowerCase()] ?? { label: type || 'Other', icon: 'file' }
}

/** Format a file size from bytes into a human-readable label. */
export function formatSize(bytes) {
  if (bytes == null) return '—'
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)} TB`
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`
  return `${bytes} B`
}

/** Format an ISO timestamp for display (locale-aware, compact). */
export function formatAcquired(isoTs) {
  if (!isoTs) return '—'
  try {
    const d = new Date(isoTs)
    if (isNaN(d.getTime())) return String(isoTs)
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return String(isoTs)
  }
}

/** Truncate a sha256 to the standard display form: first 16 chars + "…". */
export function shortHash(sha256) {
  if (!sha256) return '—'
  return `${sha256.slice(0, 16)}…`
}

/**
 * Derive summary counts from an evidence item array — used for the stat tiles.
 * @param {Array} items - EVIDENCE_ITEMS array
 * @returns {{ sealed, total, pendingSeal, unsealed, writeProtected }}
 */
export function evidenceSummary(items) {
  const arr = items ?? []
  const sealed = arr.filter((e) => (e.custody_status ?? '').toLowerCase() === 'sealed').length
  const unsealed = arr.filter((e) => (e.custody_status ?? '').toLowerCase() === 'unsealed').length
  const pendingSeal = arr.filter((e) => (e.custody_status ?? '').toLowerCase() === 'pending').length
  const writeProtected = arr.filter((e) => e.write_protected).length
  return { sealed, total: arr.length, pendingSeal, unsealed, writeProtected }
}
