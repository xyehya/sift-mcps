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

export function extractDate(ts) {
  if (!ts) return ''
  if (typeof ts === 'string' && ts.endsWith('Z') && ts.length >= 10) {
    return ts.substring(0, 10)
  }
  try {
    return new Date(ts).toISOString().substring(0, 10)
  } catch {
    return ''
  }
}

export function extractTime(ts) {
  if (!ts) return ''
  if (typeof ts === 'string' && ts.endsWith('Z') && ts.length >= 19) {
    return ts.substring(11, 19)
  }
  try {
    return new Date(ts).toISOString().substring(11, 19)
  } catch {
    return ''
  }
}
