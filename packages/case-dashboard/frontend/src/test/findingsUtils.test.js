import { describe, expect, it } from 'vitest'
import {
  buildEditItem,
  buildStageItem,
  effectiveFinding,
  filterFindings,
  getTagString,
  reviewCounts,
  upsertDelta,
} from '@/components/findings/findings-utils'

const F = [
  { id: 'F-1', status: 'draft', confidence: 'HIGH', host: 'WS1', title: 'alpha', affected_account: 'svc' },
  { id: 'F-2', status: 'approved', confidence: 'LOW', host: 'WS2', title: 'beta', account: 'm.reyes' },
  { id: 'F-3', status: 'rejected', confidence: 'MEDIUM', host: 'WS1', title: 'gamma' },
  { id: 'F-4', status: 'DRAFT', confidence: 'SPECULATIVE', host: 'WS3', title: 'delta', affected_account: ['a', { value: 'b' }] },
]

describe('filterFindings', () => {
  it('filters by status (case-insensitive draft → pending)', () => {
    expect(filterFindings(F, { filter: 'pending' }).map((f) => f.id)).toEqual(['F-1', 'F-4'])
    expect(filterFindings(F, { filter: 'approved' }).map((f) => f.id)).toEqual(['F-2'])
    expect(filterFindings(F, { filter: 'rejected' }).map((f) => f.id)).toEqual(['F-3'])
    expect(filterFindings(F, { filter: 'all' })).toHaveLength(4)
  })

  it('filters by host (case-insensitive) and free-text search', () => {
    expect(filterFindings(F, { filter: 'all', host: 'ws1' }).map((f) => f.id)).toEqual(['F-1', 'F-3'])
    expect(filterFindings(F, { filter: 'all', search: 'BET' }).map((f) => f.id)).toEqual(['F-2'])
  })

  it('filters by account, including the explicit empty-string no-account case', () => {
    expect(filterFindings(F, { filter: 'all', account: 'svc' }).map((f) => f.id)).toEqual(['F-1'])
    expect(filterFindings(F, { filter: 'all', account: 'b' }).map((f) => f.id)).toEqual(['F-4'])
    expect(filterFindings(F, { filter: 'all', account: '' }).map((f) => f.id)).toEqual(['F-3'])
  })
})

describe('reviewCounts', () => {
  it('counts draft vs reviewed', () => {
    expect(reviewCounts(F)).toEqual({ pending: 2, reviewed: 2 })
  })
})

describe('delta builders preserve the /api/delta contract', () => {
  it('buildStageItem shapes an approve/reject item', () => {
    const item = buildStageItem({ id: 'F-1', content_hash: 'abc' }, 'approve')
    expect(item).toMatchObject({ id: 'F-1', type: 'finding', action: 'approve', content_hash_at_review: 'abc', modifications: {} })
  })

  it('buildEditItem merges field modifications into an existing edit item', () => {
    const first = buildEditItem(null, { id: 'F-1' }, 'confidence', 'LOW', 'HIGH')
    expect(first.action).toBe('edit')
    expect(first.modifications.confidence).toEqual({ original: 'LOW', modified: 'HIGH' })
    const second = buildEditItem(first, { id: 'F-1' }, 'title', 'a', 'b')
    expect(Object.keys(second.modifications)).toEqual(['confidence', 'title'])
  })

  it('upsertDelta replaces an item by id (whole-document semantics)', () => {
    const delta = [{ id: 'F-1', action: 'approve' }, { id: 'F-2', action: 'reject' }]
    const next = upsertDelta(delta, { id: 'F-1', action: 'reject' })
    expect(next).toHaveLength(2)
    expect(next.find((d) => d.id === 'F-1').action).toBe('reject')
  })
})

describe('effectiveFinding + getTagString', () => {
  it('overlays staged modifications onto the base finding', () => {
    const eff = effectiveFinding({ id: 'F-1', confidence: 'LOW' }, { modifications: { confidence: { modified: 'HIGH' } } })
    expect(eff.confidence).toBe('HIGH')
  })
  it('normalises string and { value } tag forms', () => {
    expect(getTagString('T1059')).toBe('T1059')
    expect(getTagString({ value: '1.2.3.4' })).toBe('1.2.3.4')
  })
})
