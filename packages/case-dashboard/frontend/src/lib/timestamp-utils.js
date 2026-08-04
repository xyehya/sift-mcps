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
 * Fast-path string slicing to extract the date ('YYYY-MM-DD') from a timestamp,
 * avoiding the overhead of new Date(ts).toISOString() in hot loops.
 */
export function extractDate(value) {
  if (typeof value === 'string' && value.endsWith('Z') && value.length >= 10) {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(0, 10)
}

/**
 * Fast-path string slicing to extract the time ('HH:MM:SS') from a timestamp,
 * avoiding the overhead of new Date(ts).toISOString() in hot loops.
 */
export function extractTime(value) {
  if (typeof value === 'string' && value.endsWith('Z') && value.length >= 19) {
    return value.substring(11, 19)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(11, 19)
}
