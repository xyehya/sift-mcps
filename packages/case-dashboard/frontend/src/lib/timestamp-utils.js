export function parseTimestamp(value) {
  if (value instanceof Date) return value.getTime()
  if (typeof value === 'number') return Number.isFinite(value) ? value : Number.NaN
  if (typeof value === 'string') return Date.parse(value)
  return Number.NaN
}

/**
 * Fast-path extraction of the date component (YYYY-MM-DD) from a timestamp
 * to avoid `new Date()` allocation overhead in hot loops.
 */
export function extractDate(ts) {
  if (!ts) return ''
  // Only use fast path if it's explicitly UTC (ends with Z) or just a date string (length 10)
  if (typeof ts === 'string' && ts.length >= 10 && ts[4] === '-' && ts[7] === '-' && (ts.endsWith('Z') || ts.length === 10)) {
    return ts.substring(0, 10)
  }
  const ms = parseTimestamp(ts)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(0, 10)
}

/**
 * Fast-path extraction of the time component (HH:MM:SS) from a timestamp
 * to avoid `new Date()` allocation overhead in hot loops.
 */
export function extractTime(ts) {
  if (!ts) return ''
  // Only use fast path if it's explicitly UTC (ends with Z)
  if (typeof ts === 'string' && ts.length >= 19 && ts[10] === 'T' && ts[13] === ':' && ts[16] === ':' && ts.endsWith('Z')) {
    return ts.substring(11, 19)
  }
  const ms = parseTimestamp(ts)
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().substring(11, 19)
}
