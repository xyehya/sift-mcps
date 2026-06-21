import { getChainStatus, postChainSeal, postChainVerifyHmac } from '@/api/endpoints'

import { runGuard } from '@/components/evidence/custody-guard'

// ─────────────────────────────────────────────────────────────────────────
// useCustodySealActions — the password-guarded, NON-ledgered custody-integrity
// handlers: verify-HMAC and seal-manifest. Both re-auth with the runGuard
// password check (no reason needed). Seal success refreshes the evidence list
// via afterSuccess(refreshData). Mock/real split is at the API adapter layer.
// ─────────────────────────────────────────────────────────────────────────

export function useCustodySealActions({
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
}) {
  const guard = (needReason) =>
    runGuard({ needReason, modalPassword, modalReason, setModalLoading, setModalError, setModalResult })

  async function handleVerifyHmac(e) {
    e.preventDefault()
    if (!guard(false)) return
    try {
      const res = await postChainVerifyHmac({ password: modalPassword })
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
    if (!guard(false)) return
    try {
      const fileSpecs = (chainStatus?.unregistered ?? []).map((path) => ({
        path,
        source: unregisteredMetadata[path]?.source || '',
        description: unregisteredMetadata[path]?.description || '',
      }))
      const res = await postChainSeal({ password: modalPassword, file_specs: fileSpecs })
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

  return { handleVerifyHmac, handleSealEvidence }
}
