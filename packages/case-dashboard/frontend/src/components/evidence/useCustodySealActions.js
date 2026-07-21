import {
  getChainStatus,
  postCustodySeal,
  postChainSealResume,
  postFullVerifyEvidence,
} from '@/api/endpoints'

import { runGuard } from '@/components/evidence/custody-guard'

// ─────────────────────────────────────────────────────────────────────────
// useCustodySealActions — operator custody handlers. Full Verify Evidence
// re-hashes mounted bytes against database custody authority without a new
// password ceremony; Add/Seal requires re-authentication and a justification
// and retains one CSPRNG idempotency key across retries of the same modal intent.
// Seal success refreshes the evidence list via afterSuccess(refreshData).
// Mock/real split is at the API adapter layer.
// ─────────────────────────────────────────────────────────────────────────

export function useCustodySealActions({
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
}) {
  const guard = (needReason) =>
    runGuard({ needReason, modalPassword, modalReason, setModalLoading, setModalError, setModalResult })

  async function handleFullVerifyEvidence(e) {
    e.preventDefault()
    setModalLoading(true)
    setModalError('')
    setModalResult(null)
    try {
      const res = await postFullVerifyEvidence({})
      setModalResult(res)
      const status = await getChainStatus()
      if (status) setChainStatus(status)
    } catch (err) {
      setModalError(err.message || 'Verification failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleSealEvidence(e) {
    e.preventDefault()
    if (!guard(true)) return
    try {
      // PF-009: Add & Seal drives the canonical two-phase custody route
      // (begin -> commit). Every target binds to the REAL snapshot the latest
      // Refresh produced (chainStatus.snapshot_observation_id, a number from
      // gate_status' max(admission_observations.id)) — never synthesized, defaulted,
      // inferred from time, or taken from operator-entered metadata. storage_profile
      // is entirely server-owned inside the custody domain (no client field).
      const snapshotId = chainStatus?.snapshot_observation_id
      if (typeof snapshotId !== 'number') {
        throw new Error('Refresh custody status before sealing (no current snapshot).')
      }
      const targets = (chainStatus?.unregistered ?? []).map((path) => {
        const source = unregisteredMetadata[path]?.source
        const target = { display_path: path, snapshot_observation_id: snapshotId }
        if (source) target.source = source
        return target
      })
      // Phase 1 — begin: fresh password + reason authorize the selected snapshot set.
      await postCustodySeal({
        phase: 'begin',
        password: modalPassword,
        reason: modalReason,
        idempotency_key: sealIntentId,
        targets,
      })
      // Phase 2 — commit: same idempotency key + targets; the single-shot happy
      // path consumes begin's authorization (no re-auth). Only COMMITTED is sealed.
      const committed = await postCustodySeal({
        phase: 'commit',
        idempotency_key: sealIntentId,
        targets,
      })
      if (committed?.phase !== 'COMMITTED') {
        throw new Error(committed?.error || 'Seal did not complete')
      }
      // Map the canonical SealResult (phase === 'COMMITTED') to the modal's success
      // shape (`sealed: true`) so the existing EvidenceSealModal renders unchanged.
      setModalResult({ ...committed, sealed: true })
      addToast(`Manifest version ${committed.manifest_version} sealed successfully!`, 'success')
      afterSuccess(refreshData)
    } catch (err) {
      setModalError(err.message || 'Seal failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleResumeSeal(e) {
    e.preventDefault()
    if (!guard(false)) return
    try {
      const res = await postChainSealResume({
        password: modalPassword,
        operation_id: chainStatus?.incomplete_operation?.operation_id,
      })
      if (!res.sealed) throw new Error(res.error || 'Resume failed')
      setModalResult(res)
      addToast(`Manifest version ${res.manifest_version} sealed successfully!`, 'success')
      afterSuccess(refreshData)
    } catch (err) {
      setModalError(err.message || 'Resume failed')
    } finally {
      setModalLoading(false)
    }
  }

  return {
    handleFullVerifyEvidence,
    handleSealEvidence,
    handleResumeSeal,
  }
}
