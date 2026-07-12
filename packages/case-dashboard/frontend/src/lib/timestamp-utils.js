/**
 * Convert a supported timestamp value to epoch milliseconds without allocating
 * a Date for ISO strings. Invalid and unsupported values intentionally return
 * NaN so callers can preserve their existing invalid-data policy.
 */
/**
 * Fast path to extract the "YYYY-MM-DD" portion from an ISO string, falling
 * back to Date.toISOString() for other types. Avoids allocating a Date object
 * for valid ISO string inputs.
 */
export function formatISODate(value) {
  if (typeof value === 'string' && value.length >= 10 && value[4] === '-' && value[7] === '-') {
    return value.substring(0, 10)
  }
  return new Date(value).toISOString().substring(0, 10)
}

/**
 * Fast path to extract the "HH:MM:SS" portion from an ISO string, falling
 * back to Date.toISOString() for other types. Avoids allocating a Date object
 * for valid ISO string inputs.
 */
export function formatISOTime(value) {
  if (typeof value === 'string' && value.length >= 19 && value[10] === 'T') {
    return value.substring(11, 19)
  }
  return new Date(value).toISOString().substring(11, 19)
}

export function parseTimestamp(value) {
  if (value instanceof Date) return value.getTime()
  if (typeof value === 'number') return Number.isFinite(value) ? value : Number.NaN
  if (typeof value === 'string') return Date.parse(value)
  return Number.NaN
}
