import { describe, it, expect, vi, beforeEach } from 'vitest'

// CP3 r2 — the passive 15s poll and the operator Refresh call the SAME evidence
// endpoints; only Refresh may reconcile server-side. The wire signal is a
// `?refresh=1` query param the builders append ONLY for `{ refresh: true }`.
// A revert that always (or never) appends it fails here.

vi.mock('@/api/client', () => ({
  apiFetch: vi.fn(async () => ({})),
  apiPost: vi.fn(),
  apiPatch: vi.fn(),
  apiDelete: vi.fn(),
  LONG_TIMEOUT_MS: 1000,
}))

import { apiFetch } from '@/api/client'
import { getChainStatus, getEvidence } from '@/api/endpoints'

beforeEach(() => apiFetch.mockClear())

describe('CP3 r2 — evidence refresh endpoint builders', () => {
  it('getChainStatus() passive read hits the base path (poll never mutates)', () => {
    getChainStatus()
    expect(apiFetch).toHaveBeenCalledWith('/api/evidence/chain/status')
  })

  it('getChainStatus({ refresh: true }) appends ?refresh=1 (explicit Refresh)', () => {
    getChainStatus({ refresh: true })
    expect(apiFetch).toHaveBeenCalledWith('/api/evidence/chain/status?refresh=1')
  })

  it('getEvidence() passive read hits the base path', () => {
    getEvidence()
    expect(apiFetch).toHaveBeenCalledWith('/api/evidence')
  })

  it('getEvidence({ refresh: true }) appends ?refresh=1', () => {
    getEvidence({ refresh: true })
    expect(apiFetch).toHaveBeenCalledWith('/api/evidence?refresh=1')
  })
})
