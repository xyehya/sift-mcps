import { useState } from 'react'

import {
  getEvidence,
  getChainStatus,
  postChainAnchor,
  postChainProofExport,
  postVerifyLedger,
  postRotateSigningKey,
  postVerifyEvidence,
} from '@/api/endpoints'

import { useCustodySealActions } from '@/components/evidence/useCustodySealActions'
import { useCustodyLedgerActions } from '@/components/evidence/useCustodyLedgerActions'

// ─────────────────────────────────────────────────────────────────────────
// useEvidenceActions — composes the custody action handlers: the password-
// guarded Add/Seal and Full Verify Evidence pair (useCustodySealActions), the reason-guarded
// ledgered mutations (useCustodyLedgerActions), plus the unguarded async-toast
// actions (refresh · anchor · proof-export · per-item verify) it owns directly.
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
  sealIntentId,
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
    sealIntentId,
    pendingPath,
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
    sealIntentId,
    pendingPath,
    setModalLoading,
    setModalError,
    setModalResult,
    afterSuccess,
  })

  async function handleRefreshCustody() {
    try {
      addToast('Refreshing custody status…', 'info')
      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)
      const ev = await getEvidence()
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

  async function handleVerifyLedger() {
    try {
      addToast('Verifying custody ledger and signatures…', 'info')
      const result = await postVerifyLedger()
      addToast(result.verified ? 'Custody ledger verified.' : 'Custody ledger verification found violations.', result.verified ? 'success' : 'warning')
      return result
    } catch (err) {
      addToast(err.message || 'Ledger verification failed', 'error')
      return null
    }
  }

  async function handleRotateSigningKey() {
    try {
      setModalLoading(true)
      const result = await postRotateSigningKey({ password: modalPassword, reason: modalReason })
      addToast(`Custody signing key rotated: ${(result.rotation?.key_id || '').slice(0, 22)}`, 'success')
      await refreshData()
      return result
    } catch (err) {
      setModalError(err.message || 'Signing-key rotation failed')
      return null
    } finally {
      setModalLoading(false)
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
    handleRefreshCustody,
    handleTriggerAnchor,
    handleProofExport,
    handleVerifyLedger,
    handleRotateSigningKey,
    handleVerifyEvidence,
  }
}
