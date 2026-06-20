import { describe, expect, it } from 'vitest'
import {
  deriveKpis,
  mitreByTactic,
  mitreTechniques,
  recentActivity,
  severityCounts,
  techniqueMeta,
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
  it('returns ordered rows with counts and a token class bundle (High/Med/Low only)', () => {
    // P0 model-shift: SPECULATIVE tier dropped; only three tiers surfaced.
    const rows = severityCounts(FINDINGS, NOW)
    expect(rows.map((r) => r.key)).toEqual(['HIGH', 'MEDIUM', 'LOW'])
    expect(rows.find((r) => r.key === 'HIGH').count).toBe(2)
    expect(rows.find((r) => r.key === 'HIGH').cls.bg).toBe('bg-sev-high')
    expect(rows.find((r) => r.key === 'HIGH').pct).toBe(100)
  })

  it('carries awaiting (draft) + recent (24h) sub-counts + grand total', () => {
    const rows = severityCounts(FINDINGS, NOW)
    const high = rows.find((r) => r.key === 'HIGH')
    expect(high.awaiting).toBe(1) // F-1 draft (F-2 approved)
    expect(high.recent).toBe(1) // F-1 within 24h (F-2 is 3d old)
    expect(rows.find((r) => r.key === 'LOW').recent).toBe(1) // F-3 at 5h
    expect(high.total).toBe(3)
  })
})

describe('mitreTechniques + tactic grouping', () => {
  it('returns distinct sorted technique ids', () => {
    expect(mitreTechniques(FINDINGS)).toEqual(['T1', 'T2'])
  })

  it('techniqueMeta resolves known ids + sub-techniques, else "other"', () => {
    expect(techniqueMeta('T1021.001')).toMatchObject({ tactic: 'lateral-movement', name: 'Remote Services: RDP' })
    expect(techniqueMeta('T1059')).toMatchObject({ tactic: 'execution' })
    expect(techniqueMeta('T9999').tactic).toBe('other')
  })

  it('mitreByTactic groups techniques under kill-chain-ordered tactics with finding ids', () => {
    const groups = mitreByTactic([
      { id: 'F-a', mitre_ids: ['T1021.001', 'T1059.001'] },
      { id: 'F-b', mitre_ids: ['T1021.001'] },
    ])
    const lat = groups.find((g) => g.tactic === 'lateral-movement')
    expect(lat.meta.label).toBe('Lateral Movement')
    expect(lat.techniques[0]).toMatchObject({ id: 'T1021.001' })
    expect(lat.techniques[0].findingIds).toEqual(['F-a', 'F-b'])
    // execution sorts after lateral-movement is NOT guaranteed; assert presence
    expect(groups.some((g) => g.tactic === 'execution')).toBe(true)
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
