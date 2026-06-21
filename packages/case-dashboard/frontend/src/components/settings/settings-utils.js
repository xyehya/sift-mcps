// ─────────────────────────────────────────────────────────────────────────
// Settings — pure helpers + token-class maps for the agent/service JWT
// principal console (no JSX / no store), so the TTL / status derivation stays
// unit-testable and the component files stay clean under react-refresh's
// only-export-components rule.
//
// IMPORTANT: every Tailwind class below is a STATIC literal so the JIT emits it
// (AGENTS §3/§5). The legacy `--cyan-dim` / `--*-dim` accents are replaced with
// the jade/amber/graphite token scale (no legacy tokens, DESIGN-SYSTEM.md).
// ─────────────────────────────────────────────────────────────────────────

/** Coerce a value (epoch-seconds number OR ISO string) to epoch-ms or null. */
export function dateMs(value) {
  if (!value) return null
  const parsed = typeof value === 'number' ? value * 1000 : Date.parse(value)
  return Number.isFinite(parsed) ? parsed : null
}

/** Human date-time string, or "Not recorded" for missing/invalid input. */
export function formatDateTime(value) {
  const ms = dateMs(value)
  return ms === null ? 'Not recorded' : new Date(ms).toLocaleString()
}

/** Remaining TTL ("3d 4h" / "5h 12m" / "20m" / "Expired" / "Not recorded"). */
export function formatTtl(expiresAt, nowMs) {
  const expiresMs = dateMs(expiresAt)
  if (expiresMs === null) return 'Not recorded'
  const remaining = Math.max(0, expiresMs - nowMs)
  if (remaining <= 0) return 'Expired'
  const totalMinutes = Math.floor(remaining / 60000)
  const days = Math.floor(totalMinutes / 1440)
  const hours = Math.floor((totalMinutes % 1440) / 60)
  const minutes = totalMinutes % 60
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

/** Derive a principal's effective status (revoked/disabled/archived/expired/active). */
export function principalStatus(principal, nowMs) {
  const raw = String(principal.status || 'active').toLowerCase()
  if (['revoked', 'disabled', 'archived'].includes(raw)) return raw
  const expiresMs = dateMs(principal.last_issued_expires_at)
  if (expiresMs !== null && expiresMs <= nowMs) return 'expired'
  return raw
}

/** Token-type display label. */
export function tokenTypeLabel(principal) {
  return principal.token_type === 'supabase_jwt' ? 'Supabase JWT' : principal.token_type || 'JWT session'
}

// Status → token chip classes (literal map; JIT-safe).
const STATUS_CHIP = {
  active: 'text-status-approved bg-jade/10 border-jade/30',
  expired: 'text-status-pending bg-amber/10 border-amber/30',
}

/** Token chip classes for a derived principal status. */
export function statusChipClass(status) {
  return STATUS_CHIP[status] || 'text-muted-foreground bg-bg-raised border-border-soft'
}

/** Whether a principal is already revoked/disabled/archived (revoke disabled). */
export function isRevoked(principal) {
  return ['revoked', 'disabled', 'archived'].includes(String(principal.status || '').toLowerCase())
}
