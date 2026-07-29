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
 * Fast-path date extraction for valid ISO 8601 UTC strings.
 * Falls back to full Date parsing if the string isn't standard or isn't a string.
 */
export function extractDate(value) {
  if (typeof value === 'string' && value.length >= 20 && value.endsWith('Z') && value[10] === 'T') {
    return value.substring(0, 10)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(0, 10)
}

/**
 * Fast-path time extraction for valid ISO 8601 UTC strings.
 * Falls back to full Date parsing if the string isn't standard or isn't a string.
 */
export function extractTime(value) {
  if (typeof value === 'string' && value.length >= 20 && value.endsWith('Z') && value[10] === 'T') {
    return value.substring(11, 19)
  }
  const ms = parseTimestamp(value)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(11, 19)
}
