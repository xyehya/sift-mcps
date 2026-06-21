import { useState } from 'react'

import {
  getEvidence,
  getChainStatus,
  postChainRescan,
  postChainAnchor,
  postChainProofExport,
  postVerifyEvidence,
} from '@/api/endpoints'

import { useCustodySealActions } from '@/components/evidence/useCustodySealActions'
import { useCustodyLedgerActions } from '@/components/evidence/useCustodyLedgerActions'

// ─────────────────────────────────────────────────────────────────────────
// useEvidenceActions — composes the custody action handlers: the password-
// guarded seal/verify-HMAC pair (useCustodySealActions), the reason-guarded
// ledgered mutations (useCustodyLedgerActions), plus the unguarded async-toast
// actions (rescan · anchor · proof-export · per-item verify) it owns directly.
// Reads the evidence list/refresh from useEvidenceData; modal field state stays
// in the tab. Mock/real split is at the API adapter layer (AGENTS §3).
// ─────────────────────────────────────────────────────────────────────────

export function useEvidenceActions({
  chainStatus,
  setChainStatus,
  setEvidence,
  refreshData,
  addToast,
  modalPassword,
  modalReason,
  pendingPath,
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
    unregisteredMetadata,
    setModalLoading,
    setModalError,
    setModalResult,
    afterSuccess,
  })

  const ledgerActions = useCustodyLedgerActions({
    refreshData,
    addToast,
    modalPassword,
    modalReason,
    pendingPath,
    setModalLoading,
    setModalError,
    setModalResult,
    afterSuccess,
  })

  async function handleRescan() {
    try {
      addToast('Rescanning evidence directory…', 'info')
      const freshStatus = await postChainRescan()
      if (freshStatus) setChainStatus(freshStatus)
      const ev = await getEvidence()
      setEvidence(ev || [])
      addToast('Evidence chain rescan completed', 'success')
    } catch (ex) {
      addToast(ex.message || 'Rescan failed', 'error')
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
    ...ledgerActions,
    handleRescan,
    handleTriggerAnchor,
    handleProofExport,
    handleVerifyEvidence,
  }
}
