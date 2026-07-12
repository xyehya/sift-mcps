import { describe, it, expect } from 'vitest'

import { parseTimestamp } from '@/lib/timestamp-utils'

// ─────────────────────────────────────────────────────────────────────────
// timestamp-utils — direct unit tests against the low-level parser (P2.3).
// entity-utils re-exports parseTimestamp and covers it indirectly; these tests
// pin the lib module itself so the contract (string | number | Date | invalid
// → epoch ms or NaN) can't silently drift underneath its consumers.
// ─────────────────────────────────────────────────────────────────────────

describe('parseTimestamp — Date inputs', () => {
  it('returns getTime() for a valid Date', () => {
    const d = new Date('2026-01-02T03:04:05.000Z')
    expect(parseTimestamp(d)).toBe(d.getTime())
  })

  it('returns NaN for an invalid Date', () => {
    expect(Number.isNaN(parseTimestamp(new Date('not-a-date')))).toBe(true)
  })
})

describe('parseTimestamp — number inputs', () => {
  it('passes finite epoch milliseconds through unchanged', () => {
    expect(parseTimestamp(0)).toBe(0)
    expect(parseTimestamp(1_767_322_045_000)).toBe(1_767_322_045_000)
    expect(parseTimestamp(-1000)).toBe(-1000)
  })

  it('returns NaN for non-finite numbers', () => {
    expect(Number.isNaN(parseTimestamp(Number.POSITIVE_INFINITY))).toBe(true)
    expect(Number.isNaN(parseTimestamp(Number.NEGATIVE_INFINITY))).toBe(true)
    expect(Number.isNaN(parseTimestamp(Number.NaN))).toBe(true)
  })
})

describe('parseTimestamp — string inputs', () => {
  it('parses ISO 8601 strings to epoch milliseconds', () => {
    const iso = '2026-01-02T03:04:05.000Z'
    expect(parseTimestamp(iso)).toBe(Date.parse(iso))
  })

  it('parses date-only strings', () => {
    expect(parseTimestamp('2026-01-02')).toBe(Date.parse('2026-01-02'))
  })

  it('returns NaN for unparseable strings', () => {
    expect(Number.isNaN(parseTimestamp('not-a-date'))).toBe(true)
    expect(Number.isNaN(parseTimestamp(''))).toBe(true)
  })
})

describe('parseTimestamp — unsupported inputs', () => {
  it('returns NaN for null, undefined, boolean, object, and array', () => {
    expect(Number.isNaN(parseTimestamp(null))).toBe(true)
    expect(Number.isNaN(parseTimestamp(undefined))).toBe(true)
    expect(Number.isNaN(parseTimestamp(true))).toBe(true)
    expect(Number.isNaN(parseTimestamp({}))).toBe(true)
    expect(Number.isNaN(parseTimestamp([]))).toBe(true)
  })
})
