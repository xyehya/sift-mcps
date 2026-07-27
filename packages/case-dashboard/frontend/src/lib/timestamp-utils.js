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
 * Fast-path date extraction for valid ISO UTC strings to avoid new Date() allocation overhead.
 * Falls back to Date instantiation for invalid/non-UTC strings.
 */
export function extractDate(value) {
  if (!value) return '—'
  if (typeof value === 'string' && value.length >= 10 && value.endsWith('Z')) {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return '—'
  return new Date(ms).toISOString().substring(0, 10)
}

/**
 * Fast-path time extraction for valid ISO UTC strings to avoid new Date() allocation overhead.
 * Falls back to Date instantiation for invalid/non-UTC strings.
 */
export function extractTime(value) {
  if (!value) return '—'
  if (typeof value === 'string' && value.length >= 19 && value.endsWith('Z')) {
    const tIndex = value.indexOf('T')
    if (tIndex !== -1 && tIndex + 9 <= value.length) {
      return value.substring(tIndex + 1, tIndex + 9)
    }
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return '—'
  return new Date(ms).toISOString().substring(11, 19)
}
