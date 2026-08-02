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
 * Fast-path extraction of the YYYY-MM-DD date component from an ISO string,
 * bypassing `new Date()` allocation overhead for explicitly UTC values.
 * Falls back to Date allocation for unparseable or non-UTC strings.
 */
export function extractDate(value) {
  if (typeof value === 'string' && value.endsWith('Z') && value.length >= 10) {
    return value.substring(0, 10)
  }
  const ts = parseTimestamp(value)
  return Number.isNaN(ts) ? '' : new Date(ts).toISOString().substring(0, 10)
}

/**
 * Fast-path extraction of the HH:MM:SS time component from an ISO string,
 * bypassing `new Date()` allocation overhead for explicitly UTC values.
 * Falls back to Date allocation for unparseable or non-UTC strings.
 */
export function extractTime(value) {
  if (typeof value === 'string' && value.endsWith('Z') && value.length >= 19 && value.includes('T')) {
    return value.substring(11, 19)
  }
  const ts = parseTimestamp(value)
  return Number.isNaN(ts) ? '' : new Date(ts).toISOString().substring(11, 19)
}
