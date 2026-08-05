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
 * Fast-path extraction of the date part (YYYY-MM-DD) from a UTC ISO string.
 * Avoids Date allocation if the string explicitly ends in 'Z'.
 */
export function extractDate(value) {
  if (typeof value === 'string' && value.endsWith('Z') && value.length >= 10) {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  return Number.isNaN(ms) ? '' : new Date(ms).toISOString().substring(0, 10)
}

/**
 * Fast-path extraction of the time part (HH:MM:SS) from a UTC ISO string.
 * Avoids Date allocation if the string explicitly ends in 'Z'.
 */
export function extractTime(value) {
  if (typeof value === 'string' && value.endsWith('Z') && value.length >= 19) {
    return value.substring(11, 19)
  }
  const ms = parseTimestamp(value)
  return Number.isNaN(ms) ? '' : new Date(ms).toISOString().substring(11, 19)
}
