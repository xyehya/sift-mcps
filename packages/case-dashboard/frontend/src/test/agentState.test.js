import { describe, expect, it } from 'vitest'

import {
  agentSynopsis,
  deriveAgentState,
  gatedActions,
  missionTiles,
  policyGates,
  riskMeta,
  statusCounts,
  systemBlockers,
} from '../lib/agent-state'

const PORTAL = {
  agent: { state: 'awaiting-authorization', metrics: { records_parsed: 1284402, findings_proposed: 47, sources_fused: 3 } },
  gated_actions: [
    { id: 'a', title: 'Acquire memory', tool: 'mcp:acquire.memory', icon: 'cpu', risk: 'irreversible' },
    { id: 'b', title: 'Unseal', tool: 'mcp:evidence.unseal', icon: 'lock-open', risk: 'reauth' },
  ],
  backends: { up: 7, total: 8, degraded: ['yara'] },
  evidence: { sealed: 12, total: 14 },
  iocs: { total: 23, hosts: 9, accounts: 31 },
  severity: { open: 6, awaiting: 3 },
}

describe('deriveAgentState', () => {
  it('uses the portalState agent state + metrics when present', () => {
    const a = deriveAgentState(PORTAL, null, [])
    expect(a.key).toBe('awaiting-authorization')
    expect(a.label).toBe('Awaiting authorization')
    expect(a.glow).toBe(true)
    expect(a.queued).toBe(2)
    expect(a.metrics.map((m) => m.value)).toEqual([1284402, 47, 3])
  })

  it('falls back to chain violation → halt', () => {
    expect(deriveAgentState(null, { status: 'violation' }, []).key).toBe('halt')
  })

  it('falls back to staged delta → awaiting-authorization', () => {
    expect(deriveAgentState(null, { status: 'ok' }, [{ id: 'F-1' }]).key).toBe('awaiting-authorization')
  })

  it('is idle with no signals and metrics default to zero', () => {
    const a = deriveAgentState(null, null, [])
    expect(a.key).toBe('idle')
    expect(a.metrics.every((m) => m.value === 0)).toBe(true)
  })
})

describe('gatedActions + riskMeta', () => {
  it('normalises gated actions and defaults missing fields', () => {
    const list = gatedActions(PORTAL)
    expect(list).toHaveLength(2)
    expect(list[0]).toMatchObject({ id: 'a', tool: 'mcp:acquire.memory', icon: 'cpu', risk: 'irreversible' })
    expect(gatedActions(null)).toEqual([])
  })

  it('maps risk → token-class bundle with a label', () => {
    expect(riskMeta('irreversible').text).toBe('text-sev-high')
    expect(riskMeta('reauth').text).toBe('text-sev-med')
    expect(riskMeta('elevated').text).toBe('text-status-staged')
    expect(riskMeta('???').text).toBe('text-muted-foreground')
  })
})

describe('missionTiles', () => {
  it('builds the four KPI tiles from portalState (DB authority)', () => {
    const tiles = missionTiles(PORTAL, {})
    expect(tiles.map((t) => t.key)).toEqual(['evidence', 'high', 'iocs', 'backends'])
    const byKey = Object.fromEntries(tiles.map((t) => [t.key, t]))
    expect(byKey.evidence).toMatchObject({ value: 12, sub: '/14' })
    expect(byKey.high.value).toBe(6)
    expect(byKey.iocs.value).toBe(23)
    expect(byKey.backends).toMatchObject({ value: 7, sub: '/8 up' })
    expect(byKey.backends.foot).toMatch(/degraded · yara/)
  })

  it('falls back to chain/findings/ioc slices without portalState', () => {
    const findings = [
      { confidence: 'HIGH', status: 'draft' },
      { confidence: 'HIGH', status: 'approved' },
      { confidence: 'LOW', status: 'draft' },
    ]
    const tiles = missionTiles(null, { findings, iocs: [{ id: 1 }, { id: 2 }] })
    const byKey = Object.fromEntries(tiles.map((t) => [t.key, t]))
    expect(byKey.high.value).toBe(2) // two HIGH
    expect(byKey.high.foot).toMatch(/1 awaiting review/)
    expect(byKey.iocs.value).toBe(2)
    expect(byKey.evidence.value).toBe('—')
  })
})

describe('policyGates (HITL — exactly two triggers)', () => {
  const ACTIVE = { status: 'active' }
  it('flags the case-not-active trigger', () => {
    const gates = policyGates(PORTAL, { status: 'sealed' }, { status: 'ok' })
    expect(gates.some((g) => g.kind === 'case')).toBe(true)
  })
  it('flags evidence integrity: chain violation OR unsealed custody', () => {
    expect(policyGates({ evidence: { sealed: 5, total: 5 } }, ACTIVE, { status: 'violation' }).some((g) => g.kind === 'evidence')).toBe(true)
    const unsealed = policyGates({ evidence: { sealed: 12, total: 14 } }, ACTIVE, { status: 'ok' })
    expect(unsealed.find((g) => g.kind === 'evidence').title).toMatch(/not fully sealed/i)
  })
  it('returns NO gates when the case is active and custody is fully sealed', () => {
    expect(policyGates({ evidence: { sealed: 14, total: 14 } }, ACTIVE, { status: 'ok' })).toEqual([])
  })
  it('never emits more than the two allowed triggers', () => {
    const gates = policyGates({ evidence: { sealed: 0, total: 9 } }, { status: 'inactive' }, { status: 'violation' })
    expect(gates.length).toBeLessThanOrEqual(2)
  })
  it('degrades safely with null inputs', () => {
    expect(policyGates(null, null, null)).toEqual([])
  })
})

describe('systemBlockers (NOT policy gates)', () => {
  it('prefers explicit named blockers with detail', () => {
    const blockers = systemBlockers({ system_blockers: [{ name: 'yara', tool: 'mcp:yara.scan', detail: 'degraded' }] })
    expect(blockers).toHaveLength(1)
    expect(blockers[0]).toMatchObject({ name: 'yara', tool: 'mcp:yara.scan', detail: 'degraded' })
  })
  it('falls back to backends.degraded names', () => {
    const blockers = systemBlockers({ backends: { degraded: ['yara', 'vol'] } })
    expect(blockers.map((b) => b.name)).toEqual(['yara', 'vol'])
  })
  it('degrades to an empty list', () => {
    expect(systemBlockers(null)).toEqual([])
  })
})

describe('agentSynopsis (data-driven, never hardcoded)', () => {
  it('prefers the DB-authority headline', () => {
    expect(agentSynopsis({ agent: { headline: 'from-db' } }, { name: 'X' }, { headline: 'fallback' })).toBe('from-db')
  })
  it('composes from case metadata when no headline', () => {
    const s = agentSynopsis(null, { title: 'NORTHWIND', incident_type: 'unauthorized_access', severity: 'high', affected_systems: ['a', 'b'] }, { headline: 'Agent idle.' })
    expect(s).toMatch(/NORTHWIND/)
    expect(s).toMatch(/unauthorized access/)
    expect(s).toMatch(/2 systems in scope/)
  })
  it('falls back to the agent headline with neither', () => {
    expect(agentSynopsis(null, null, { headline: 'Agent idle.' })).toBe('Agent idle.')
  })
})

describe('statusCounts', () => {
  it('pulls custody + backend counts from portalState', () => {
    expect(statusCounts(PORTAL, null)).toEqual({
      sealed: 12,
      evidenceTotal: 14,
      backendsUp: 7,
      backendsTotal: 8,
      degraded: 1,
    })
  })

  it('degrades to nulls when nothing is known', () => {
    expect(statusCounts(null, null)).toMatchObject({ sealed: null, backendsUp: null, degraded: 0 })
  })
})
