import { useState } from 'react'

import {
  getEvidence,
  getChainStatus,
  getCustodyStatus,
  postChainAnchor,
  postChainProofExport,
  postVerifyEvidence,
} from '@/api/endpoints'

import { useCustodySealActions } from '@/components/evidence/useCustodySealActions'
import { useResolveActions } from '@/components/evidence/useResolveActions'

// ─────────────────────────────────────────────────────────────────────────
// useEvidenceActions — composes the custody action handlers: the password-
// guarded Add/Seal and Full Verify Evidence pair (useCustodySealActions), the
// batch-reauth D4 Resolve flow (useResolveActions), plus the unguarded
// async-toast actions (refresh · anchor · proof-export · per-item verify) it
// owns directly. Reads the evidence list/refresh from useEvidenceData; modal
// field state stays in the tab. Mock/real split is at the API adapter layer
// (AGENTS §3).
// ─────────────────────────────────────────────────────────────────────────

export function useEvidenceActions({
  chainStatus,
  setChainStatus,
  setEvidence,
  refreshData,
  addToast,
  modalPassword,
  modalReason,
  sealIntentId,
  pendingDispositions,
  unregisteredMetadata,
  setModalLoading,
  setModalError,
  setModalResult,
  afterSuccess,
}) {
  const [verifyStatus, setVerifyStatus] = useState({})

  const sealActions = useCustodySealActions({
    chainStatus,
    setChainStatus,
    refreshData,
    addToast,
    modalPassword,
    modalReason,
    sealIntentId,
    unregisteredMetadata,
    setModalLoading,
    setModalError,
    setModalResult,
    afterSuccess,
  })

  const resolveActions = useResolveActions({
    refreshData,
    addToast,
    modalPassword,
    modalReason,
    sealIntentId,
    dispositions: pendingDispositions,
    setModalLoading,
    setModalError,
    setModalResult,
    afterSuccess,
  })

  async function handleRefreshCustody() {
    try {
      addToast('Refreshing custody status…', 'info')
      // The SINGLE reconciliation trigger: the target custody-status route
      // reconciles exactly once server-side (SPEC pre-seal staging — one operator
      // Refresh, one read-only reconciliation). It must succeed first.
      await getCustodyStatus()
      // Then render from the legacy reads, which are PURE (never reconcile) — so
      // the passive 15s poll can never mutate custody state.
      const [freshStatus, ev] = await Promise.all([getChainStatus(), getEvidence()])
      if (freshStatus) setChainStatus(freshStatus)
      setEvidence(ev || [])
      addToast('Custody status refreshed', 'success')
    } catch (ex) {
      addToast(ex.message || 'Custody refresh failed', 'error')
    }
  }

  async function handleTriggerAnchor() {
    try {
      addToast('Submitting Solana anchor transaction…', 'info')
      const result = await postChainAnchor()
      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)
      addToast(
        result.anchored
          ? 'Manifest anchored successfully!'
          : 'Anchor submitted but not yet confirmed. Check status in a few seconds.',
        result.anchored ? 'success' : 'warning',
      )
    } catch (err) {
      addToast(err.message || 'Solana anchor failed', 'error')
    }
  }

  async function handleProofExport() {
    try {
      addToast('Generating proof export from DB custody authority…', 'info')
      const result = await postChainProofExport()
      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)
      const pe = result.proof_export ?? {}
      addToast(
        pe.verified
          ? 'Proof export generated and verified against mounted evidence.'
          : 'Proof export recorded, but evidence verification reported issues.',
        pe.verified ? 'success' : 'warning',
      )
    } catch (err) {
      addToast(err.message || 'Proof export failed', 'error')
    }
  }

  async function handleVerifyEvidence(path) {
    setVerifyStatus((prev) => ({ ...prev, [path]: 'checking' }))
    try {
      const result = await postVerifyEvidence(path)
      setVerifyStatus((prev) => ({
        ...prev,
        [path]:
          result.status === 'verified'
            ? 'verified'
            : result.status === 'failed'
              ? 'failed'
              : result.status || 'unknown',
      }))
    } catch {
      setVerifyStatus((prev) => ({ ...prev, [path]: 'error' }))
    }
  }

  return {
    verifyStatus,
    ...sealActions,
    ...resolveActions,
    handleRefreshCustody,
    handleTriggerAnchor,
    handleProofExport,
    handleVerifyEvidence,
  }
}
