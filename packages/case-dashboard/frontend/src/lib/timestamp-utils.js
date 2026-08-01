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
 * Extracts the date part (YYYY-MM-DD) from a timestamp without allocating a Date object
 * when the timestamp is a valid ISO UTC string.
 */
export function extractDate(ts) {
  if (typeof ts === 'string' && ts.length >= 10 && ts.endsWith('Z')) {
    return ts.substring(0, 10)
  }
  const ms = parseTimestamp(ts)
  if (Number.isNaN(ms)) return '—'
  return new Date(ms).toISOString().substring(0, 10)
}

/**
 * Extracts the time part (HH:MM:SS) from a timestamp without allocating a Date object
 * when the timestamp is a valid ISO UTC string.
 */
export function extractTime(ts) {
  if (typeof ts === 'string' && ts.length >= 19 && ts.endsWith('Z')) {
    return ts.substring(11, 19)
  }
  const ms = parseTimestamp(ts)
  if (Number.isNaN(ms)) return '—'
  return new Date(ms).toISOString().substring(11, 19)
}
