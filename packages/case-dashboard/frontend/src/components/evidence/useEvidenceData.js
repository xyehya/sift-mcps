import { useCallback, useEffect, useState } from 'react'

import { getEvidence, getChainStatus } from '@/api/endpoints'

// ─────────────────────────────────────────────────────────────────────────
// useEvidenceData — owns the evidence list + chain-status load. One-shot fetch
// on mount into local state, plus a `refreshData` callback the action handlers
// (useEvidenceActions) call after a successful custody mutation. Mock/real
// split lives at the API adapter layer — no isMock branching here (AGENTS §3).
// ─────────────────────────────────────────────────────────────────────────

export function useEvidenceData({ setChainStatus }) {
  const [evidence, setEvidence] = useState([])
  const [evidenceLoading, setEvidenceLoading] = useState(true)
  const [evidenceError, setEvidenceError] = useState(null)

  const refreshData = useCallback(async () => {
    setEvidenceLoading(true)
    setEvidenceError(null)
    try {
      const ev = await getEvidence()
      setEvidence(ev || [])
    } catch (e) {
      setEvidenceError(e.message || 'Failed to load evidence list')
    } finally {
      setEvidenceLoading(false)
    }
    try {
      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)
    } catch (e) {
      console.error('Failed to load chain status', e)
    }
  }, [setChainStatus])

  useEffect(() => {
    // Initial data load on mount — intentional one-shot fetch into local state.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refreshData()
  }, [refreshData])

  return { evidence, setEvidence, evidenceLoading, evidenceError, refreshData }
}
