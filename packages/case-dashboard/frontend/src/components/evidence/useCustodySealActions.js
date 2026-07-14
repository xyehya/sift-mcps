import {
  getChainStatus,
  postChainSeal,
  postChainSealResume,
  postFullVerifyEvidence,
} from '@/api/endpoints'

import { runGuard } from '@/components/evidence/custody-guard'

// ─────────────────────────────────────────────────────────────────────────
// useCustodySealActions — operator custody handlers. Full Verify Evidence
// re-hashes mounted bytes against database custody authority after password
// re-authentication; Add/Seal additionally requires a justification
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
    if (!guard(false)) return
    try {
      const res = await postFullVerifyEvidence({ password: modalPassword })
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
      const fileSpecs = (chainStatus?.unregistered ?? []).map((path) => ({
        path,
        source: unregisteredMetadata[path]?.source || '',
        description: unregisteredMetadata[path]?.description || '',
      }))
      const res = await postChainSeal({
        password: modalPassword,
        reason: modalReason,
        idempotency_key: sealIntentId,
        file_specs: fileSpecs,
      })
      if (res.sealed) {
        setModalResult(res)
        addToast(`Manifest version ${res.manifest_version} sealed successfully!`, 'success')
        afterSuccess(refreshData)
      } else {
        throw new Error(res.error || 'Seal failed')
      }
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

  return { handleFullVerifyEvidence, handleSealEvidence, handleResumeSeal }
}
