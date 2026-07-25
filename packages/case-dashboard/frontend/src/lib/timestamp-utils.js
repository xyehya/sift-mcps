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
 * Extract the date component (YYYY-MM-DD) from a timestamp.
 * Uses a fast-path for valid ISO UTC strings to avoid new Date() allocation.
 */
export function extractDate(ts) {
  if (!ts) return ''
  if (typeof ts === 'string' && ts.length >= 20 && ts.endsWith('Z') && ts[10] === 'T') {
    return ts.substring(0, 10)
  }
  const ms = parseTimestamp(ts)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(0, 10)
}

/**
 * Extract the time component (HH:MM:SS) from a timestamp.
 * Uses a fast-path for valid ISO UTC strings to avoid new Date() allocation.
 */
export function extractTime(ts) {
  if (!ts) return ''
  if (typeof ts === 'string' && ts.length >= 20 && ts.endsWith('Z') && ts[10] === 'T') {
    return ts.substring(11, 19)
  }
  const ms = parseTimestamp(ts)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(11, 19)
}
