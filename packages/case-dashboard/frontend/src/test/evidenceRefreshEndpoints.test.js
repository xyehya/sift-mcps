import { describe, it, expect, vi, beforeEach } from 'vitest'

// CP3 final fix — the single explicit Refresh trigger. Reconciliation happens in
// exactly ONE place: the target custody-status route (GET /portal/custody/status).
// The legacy chain-status/evidence reads are PURE (no ?refresh switch), so neither
// the operator Refresh nor the passive 15s poll can reconcile through them. A
// revert that re-adds a `?refresh` query to the legacy builders, or drops the
// target-route adapter, fails here.

vi.mock('@/api/client', () => ({
  apiFetch: vi.fn(async () => ({})),
  apiPost: vi.fn(),
  apiPatch: vi.fn(),
  apiDelete: vi.fn(),
  LONG_TIMEOUT_MS: 1000,
}))

import { apiFetch } from '@/api/client'
import { getChainStatus, getEvidence, getCustodyStatus } from '@/api/endpoints'

beforeEach(() => apiFetch.mockClear())

describe('CP3 — custody refresh endpoint builders (single-trigger contract)', () => {
  it('getCustodyStatus() hits the target reconcile route /portal/custody/status', () => {
    getCustodyStatus()
    // apiFetch prefixes BASE=/portal, so the relative path is /custody/status.
    expect(apiFetch).toHaveBeenCalledWith('/custody/status')
  })

  it('getChainStatus() is a pure legacy read — no ?refresh, ever', () => {
    getChainStatus()
    expect(apiFetch).toHaveBeenCalledWith('/api/evidence/chain/status')
  })

  it('getEvidence() is a pure legacy read — no ?refresh, ever', () => {
    getEvidence()
    expect(apiFetch).toHaveBeenCalledWith('/api/evidence')
  })

  it('the legacy read builders take no argument that could opt into reconciliation', () => {
    // They are nullary passive reads; passing anything must not change the URL.
    getChainStatus({ refresh: true })
    getEvidence({ refresh: true })
    expect(apiFetch).toHaveBeenCalledWith('/api/evidence/chain/status')
    expect(apiFetch).toHaveBeenCalledWith('/api/evidence')
    // No call ever carries a refresh query.
    for (const call of apiFetch.mock.calls) {
      expect(String(call[0])).not.toContain('refresh')
    }
  })
})
