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
 * Fast-path date extraction (YYYY-MM-DD). If the input is already a string
 * (like an ISO string), slice it directly. Otherwise, fall back to parsing
 * and allocating a new Date. Avoids `new Date()` allocation in hot loops.
 */
export function extractDate(value) {
  if (typeof value === 'string' && value.length >= 10) {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(0, 10)
}

/**
 * Fast-path time extraction (HH:MM:SS). If the input is already a valid ISO
 * string, slice it directly. Otherwise, fall back to parsing and allocating
 * a new Date. Avoids `new Date()` allocation in hot loops.
 */
export function extractTime(value) {
  if (typeof value === 'string' && value.length >= 19) {
    return value.substring(11, 19)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(11, 19)
}
