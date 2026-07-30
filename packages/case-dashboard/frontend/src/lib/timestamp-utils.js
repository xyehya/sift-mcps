/**
 * Convert a supported timestamp value to epoch milliseconds without allocating
 * a Date for ISO strings. Invalid and unsupported values intentionally return
 * NaN so callers can preserve their existing invalid-data policy.
 */
export function parseTimestamp(value) {
  if (value instanceof Date) return value.getTime()
  if (typeof value === 'number') return Number.isFinite(value) ? value : Number.NaN
  if (typeof value === 'string') return Date.parse(value)
  return Number.NaN
}

/**
 * Extract the date portion (YYYY-MM-DD) from an ISO timestamp string using a
 * fast-path substring if valid to avoid `new Date()` allocation overhead.
 * Falls back to Date instantiation for invalid formats or non-UTC strings.
 */
export function extractDate(value) {
  if (typeof value === 'string' && value.length >= 10 && value.endsWith('Z') && value[4] === '-' && value[7] === '-') {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  return Number.isNaN(ms) ? '—' : new Date(ms).toISOString().substring(0, 10)
}

/**
 * Extract the time portion (HH:MM:SS) from an ISO timestamp string using a
 * fast-path substring if valid to avoid `new Date()` allocation overhead.
 * Falls back to Date instantiation for invalid formats or non-UTC strings.
 */
export function extractTime(value) {
  if (typeof value === 'string' && value.length >= 19 && value.endsWith('Z') && value[10] === 'T' && value[13] === ':' && value[16] === ':') {
    return value.substring(11, 19)
  }
  const ms = parseTimestamp(value)
  return Number.isNaN(ms) ? '—' : new Date(ms).toISOString().substring(11, 19)
}
