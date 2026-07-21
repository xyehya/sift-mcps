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
 * Fast-path date extraction for ISO strings.
 * Falls back to `new Date()` for numbers, dates, or non-ISO strings.
 * Expected format: "YYYY-MM-DD"
 */
export function extractDate(value) {
  if (typeof value === 'string' && value.length >= 10 && value[4] === '-' && value[7] === '-') {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  return Number.isNaN(ms) ? '—' : new Date(ms).toISOString().substring(0, 10)
}

/**
 * Fast-path time extraction for ISO strings.
 * Falls back to `new Date()` for numbers, dates, or non-ISO strings.
 * Expected format: "HH:mm:ss"
 */
export function extractTime(value) {
  if (typeof value === 'string' && value.length >= 19 && value[10] === 'T' && value[13] === ':' && value[16] === ':') {
    return value.substring(11, 19)
  }
  const ms = parseTimestamp(value)
  return Number.isNaN(ms) ? '—' : new Date(ms).toISOString().substring(11, 19)
}
