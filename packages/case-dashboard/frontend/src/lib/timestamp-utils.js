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
 * Extracts the date component (YYYY-MM-DD) from a timestamp without allocating a Date object
 * when possible (fast path for valid ISO strings).
 */
export function extractDate(value) {
  if (!value) return ''
  if (typeof value === 'string' && value.length >= 10 && value[4] === '-' && value[7] === '-') {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(0, 10)
}

/**
 * Extracts the time component (HH:MM:SS) from a timestamp without allocating a Date object
 * when possible (fast path for valid ISO strings).
 */
export function extractTime(value) {
  if (!value) return ''
  if (typeof value === 'string' && value.length >= 19 && value[10] === 'T' && value[13] === ':' && value[16] === ':') {
    return value.substring(11, 19)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(11, 19)
}
