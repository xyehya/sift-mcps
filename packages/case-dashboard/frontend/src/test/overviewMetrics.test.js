import { describe, expect, it } from 'vitest'
import {
  deriveKpis,
  mitreTechniques,
  recentActivity,
  severityCounts,
  velocitySeries,
} from '@/components/overview/overview-metrics'

const NOW = Date.parse('2026-06-20T12:00:00Z')
const ago = (ms) => new Date(NOW - ms).toISOString()
const H = 3600 * 1000
const D = 24 * H

const FINDINGS = [
  { id: 'F-1', status: 'draft', confidence: 'HIGH', mitre_ids: ['T1', 'T2'], modified_at: ago(2 * H) },
  { id: 'F-2', status: 'approved', confidence: 'HIGH', mitre_ids: ['T2'], modified_at: ago(3 * D) },
  { id: 'F-3', status: 'draft', confidence: 'LOW', mitre_ids: [], event_timestamp: ago(5 * H) },
]

describe('deriveKpis', () => {
  it('prefers the server summary by_status, falls back to client counts', () => {
    const fromSummary = deriveKpis({ findings: { total: 9, by_status: { approved: 4, draft: 5 } } }, FINDINGS, [{ id: 'F-1' }])
    expect(fromSummary).toMatchObject({ total: 9, approved: 4, pending: 5, staged: 1 })
    const fallback = deriveKpis(null, FINDINGS, [])
    expect(fallback).toMatchObject({ total: 3, approved: 1, pending: 2, staged: 0 })
  })

  it('computes staged review percentage', () => {
    expect(deriveKpis(null, FINDINGS, [{ id: 'F-1' }, { id: 'F-3' }]).reviewPct).toBe(67)
  })
})

describe('severityCounts', () => {
  it('returns ordered rows with counts and a token class bundle', () => {
    const rows = severityCounts(FINDINGS)
    expect(rows.map((r) => r.key)).toEqual(['HIGH', 'MEDIUM', 'LOW', 'SPECULATIVE'])
    expect(rows.find((r) => r.key === 'HIGH').count).toBe(2)
    expect(rows.find((r) => r.key === 'HIGH').cls.bg).toBe('bg-sev-high')
    expect(rows.find((r) => r.key === 'HIGH').pct).toBe(100)
  })
})

describe('mitreTechniques', () => {
  it('returns distinct sorted technique ids', () => {
    expect(mitreTechniques(FINDINGS)).toEqual(['T1', 'T2'])
  })
})

describe('velocitySeries', () => {
  it('bins findings into fixed buckets for 24h', () => {
    const s = velocitySeries(FINDINGS, '24h', NOW)
    expect(s).toHaveLength(24)
    expect(s.reduce((sum, b) => sum + b.count, 0)).toBe(2) // F-1 (2h) + F-3 (5h)
  })
  it('returns an empty series when nothing is in range', () => {
    expect(velocitySeries([{ id: 'X', modified_at: ago(10 * D) }], '24h', NOW)).toEqual(
      expect.arrayContaining([expect.objectContaining({ count: 0 })]),
    )
  })
})

describe('recentActivity', () => {
  it('orders newest-first and respects the window', () => {
    const last24 = recentActivity(FINDINGS, '24h', 8, NOW)
    expect(last24.map((f) => f.id)).toEqual(['F-1', 'F-3'])
    const all = recentActivity(FINDINGS, 'all', 8, NOW)
    expect(all[0].id).toBe('F-1')
    expect(all).toHaveLength(3)
  })
})
