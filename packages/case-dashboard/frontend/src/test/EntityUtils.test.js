import { describe, it, expect } from 'vitest'

import {
  displayHost,
  bestConfidence,
  statusSummary,
  getAccountsForFinding,
  timeRange,
  fmtTs,
  normEventType,
  humanizeGap,
  filterTimeline,
  sortBy,
  confClass,
} from '@/components/common/entity-utils'

// ─────────────────────────────────────────────────────────────────────────
// entity-utils — pure aggregation/format/filter logic shared by the four
// entity tabs (Timeline · Hosts · Accounts · IOCs). These are the legacy
// behaviours the parity redo must preserve.
// ─────────────────────────────────────────────────────────────────────────

describe('entity-utils — host + confidence + status', () => {
  it('displayHost uppercases, falls back to UNKNOWN', () => {
    expect(displayHost('dc-01')).toBe('DC-01')
    expect(displayHost('')).toBe('UNKNOWN')
    expect(displayHost(null)).toBe('UNKNOWN')
  })

  it('bestConfidence picks the highest-weighted label (SPECULATIVE floor)', () => {
    expect(bestConfidence([{ confidence: 'LOW' }, { confidence: 'HIGH' }, { confidence: 'MEDIUM' }])).toBe('HIGH')
    expect(bestConfidence([{ confidence: 'LOW' }, { confidence: 'MEDIUM' }])).toBe('MEDIUM')
    expect(bestConfidence([])).toBe('SPECULATIVE')
    expect(bestConfidence([{ confidence: 'bogus' }])).toBe('SPECULATIVE')
  })

  it('confClass maps SPECULATIVE → low/steel for backward compat', () => {
    expect(confClass('SPECULATIVE').text).toBe('text-sev-low')
    expect(confClass('HIGH').text).toBe('text-sev-high')
    expect(confClass('weird').text).toBe('text-muted-foreground')
  })

  it('statusSummary tallies draft/approved/rejected (unknown → draft)', () => {
    const list = [{ status: 'approved' }, { status: 'rejected' }, { status: 'draft' }, { status: 'mystery' }, {}]
    expect(statusSummary(list)).toEqual({ draft: 3, approved: 1, rejected: 1 })
  })
})

describe('entity-utils — account extraction', () => {
  it('handles string, comma-string, array, and {value} forms', () => {
    expect(getAccountsForFinding({ affected_account: 'svc-backup' })).toEqual(['svc-backup'])
    expect(getAccountsForFinding({ affected_account: 'a, b ,c' })).toEqual(['a', 'b', 'c'])
    expect(getAccountsForFinding({ account: ['x', { value: 'y' }] })).toEqual(['x', 'y'])
    expect(getAccountsForFinding({})).toEqual([])
  })
})

describe('entity-utils — time formatting', () => {
  it('fmtTs renders UTC "YYYY-MM-DD HH:MM:SS" or — for junk', () => {
    expect(fmtTs('2026-01-02T03:04:05.000Z')).toBe('2026-01-02 03:04:05')
    expect(fmtTs('not-a-date')).toBe('—')
    expect(fmtTs(null)).toBe('—')
  })

  it('timeRange collapses single timestamps and spans min→max', () => {
    const single = [{ event_timestamp: '2026-01-02T03:04:05Z' }]
    expect(timeRange(single)).toBe('2026-01-02 03:04:05')
    const span = [{ timestamp: '2026-01-02T03:04:05Z' }, { timestamp: '2026-01-03T06:00:00Z' }]
    expect(timeRange(span)).toBe('2026-01-02 03:04:05 to 2026-01-03 06:00:00')
    expect(timeRange([{}])).toBe('—')
  })
})

describe('entity-utils — timeline', () => {
  it('normEventType reads event_type|type, clamps unknown to other', () => {
    expect(normEventType({ event_type: 'AUTH' })).toBe('auth')
    expect(normEventType({ type: 'network' })).toBe('network')
    expect(normEventType({ type: 'banana' })).toBe('other')
    expect(normEventType({})).toBe('other')
  })

  it('humanizeGap formats minutes/hours/days', () => {
    expect(humanizeGap(45 * 60000)).toBe('45m')
    expect(humanizeGap(125 * 60000)).toBe('2h 5m')
    expect(humanizeGap((24 * 60 + 180) * 60000)).toBe('1d 3h')
  })

  it('filterTimeline applies type/host/search and sorts ascending', () => {
    const tl = [
      { id: 'a', timestamp: '2026-01-02T05:00:00Z', event_type: 'auth', host: 'DC-01', description: 'login alpha' },
      { id: 'b', timestamp: '2026-01-02T03:00:00Z', event_type: 'network', host: 'WS-1', description: 'beacon bravo' },
      { id: 'c', timestamp: '2026-01-02T04:00:00Z', event_type: 'auth', host: 'WS-1', description: 'login charlie' },
    ]
    // No filters → chronological order.
    expect(filterTimeline(tl).map((e) => e.id)).toEqual(['b', 'c', 'a'])
    // Type filter.
    expect(filterTimeline(tl, { types: new Set(['auth']) }).map((e) => e.id)).toEqual(['c', 'a'])
    // Host filter.
    expect(filterTimeline(tl, { host: 'WS-1' }).map((e) => e.id)).toEqual(['b', 'c'])
    // Search (description, case-insensitive).
    expect(filterTimeline(tl, { search: 'BRAVO' }).map((e) => e.id)).toEqual(['b'])
  })
})

describe('entity-utils — sortBy', () => {
  it('sorts numerically and lexically, both directions', () => {
    const rows = [{ n: 3, s: 'b' }, { n: 1, s: 'a' }, { n: 2, s: 'c' }]
    expect(sortBy(rows, (r) => r.n, true).map((r) => r.n)).toEqual([1, 2, 3])
    expect(sortBy(rows, (r) => r.n, false).map((r) => r.n)).toEqual([3, 2, 1])
    expect(sortBy(rows, (r) => r.s, true).map((r) => r.s)).toEqual(['a', 'b', 'c'])
  })
})
