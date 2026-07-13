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
 * Fast-path extraction of the YYYY-MM-DD date part from an ISO string, falling
 * back to Date allocation for other types. Avoids allocation in hot loops.
 */
export function extractIsoDate(value, fallback = '—') {
  if (typeof value === 'string' && value.length >= 10 && value[4] === '-' && value[7] === '-') {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  return Number.isNaN(ms) ? fallback : new Date(ms).toISOString().substring(0, 10)
}

/**
 * Fast-path extraction of the HH:MM:SS time part from an ISO string, falling
 * back to Date allocation for other types. Avoids allocation in hot loops.
 */
export function extractIsoTime(value, fallback = '—') {
  if (typeof value === 'string' && value.length >= 19 && value[10] === 'T' && value[13] === ':') {
    return value.substring(11, 19)
  }
  const ms = parseTimestamp(value)
  return Number.isNaN(ms) ? fallback : new Date(ms).toISOString().substring(11, 19)
}
