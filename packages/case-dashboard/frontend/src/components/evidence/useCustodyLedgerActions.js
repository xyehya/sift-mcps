import {
  postChainIgnore,
  postChainDelete,
  postChainRetire,
  postChainReacquire,
  unsealEvidence,
} from '@/api/endpoints'

import { runGuard } from '@/components/evidence/custody-guard'

// ─────────────────────────────────────────────────────────────────────────
// useCustodyLedgerActions — the password + reason-guarded LEDGERED custody
// mutations: ignore · delete · retire · reacquire · unseal. Each re-auths with
// runGuard (reason required), then on success records via afterSuccess(
// refreshData). Mock/real split is at the API adapter layer (AGENTS §3).
// ─────────────────────────────────────────────────────────────────────────

export function useCustodyLedgerActions({
  refreshData,
  addToast,
  modalPassword,
  modalReason,
  pendingPath,
  setModalLoading,
  setModalError,
  setModalResult,
  afterSuccess,
}) {
  const guard = (needReason) =>
    runGuard({ needReason, modalPassword, modalReason, setModalLoading, setModalError, setModalResult })

  async function handleIgnoreEvidence(e) {
    e.preventDefault()
    if (!guard(true)) return
    try {
      const res = await postChainIgnore({ password: modalPassword, path: pendingPath, reason: modalReason })
      if (res.ignored) {
        addToast('File marked as ignored successfully!', 'success')
        setModalResult({ success: true })
        afterSuccess(refreshData)
      } else {
        throw new Error(res.error || 'Ignore failed')
      }
    } catch (err) {
      setModalError(err.message || 'Ignore failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleDeleteEvidence(e) {
    e.preventDefault()
    if (!guard(true)) return
    try {
      const res = await postChainDelete({ password: modalPassword, path: pendingPath, reason: modalReason })
      if (res.deleted) {
        addToast(res.file_removed ? 'File permanently deleted from evidence.' : 'Stray record removed.', 'success')
        setModalResult({ success: true })
        afterSuccess(refreshData)
      } else {
        throw new Error(res.error || 'Delete failed')
      }
    } catch (err) {
      setModalError(err.message || 'Delete failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleRetireEvidence(e) {
    e.preventDefault()
    if (!guard(true)) return
    try {
      const res = await postChainRetire({ password: modalPassword, path: pendingPath, reason: modalReason })
      if (res.ignored || res.retired || res.manifest_version !== undefined) {
        addToast('File retired successfully!', 'success')
        setModalResult({ success: true })
        afterSuccess(refreshData)
      } else {
        throw new Error(res.error || 'Retire failed')
      }
    } catch (err) {
      setModalError(err.message || 'Retire failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleReacquireEvidence(e) {
    e.preventDefault()
    if (!guard(true)) return
    try {
      const res = await postChainReacquire({ password: modalPassword, path: pendingPath, reason: modalReason })
      if (res.reacquired) {
        addToast(`Evidence re-acquired and re-sealed (manifest v${res.manifest_version}).`, 'success')
        setModalResult({ success: true })
        afterSuccess(refreshData)
      } else {
        throw new Error(res.error || 'Re-acquire failed')
      }
    } catch (err) {
      setModalError(err.message || 'Re-acquire failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleUnsealEvidence(e) {
    e.preventDefault()
    if (!guard(true)) return
    try {
      // CL3a (B-MVP-017): password re-verified against Supabase server-side.
      const res = await unsealEvidence(pendingPath, modalReason, modalPassword)
      if (res.unsealed) {
        addToast('Evidence unsealed — immutability cleared. Re-seal before agent tools can run.', 'success')
        setModalResult({ success: true })
        afterSuccess(refreshData)
      } else {
        throw new Error(res.error || 'Unseal failed')
      }
    } catch (err) {
      setModalError(err.message || 'Unseal failed')
    } finally {
      setModalLoading(false)
    }
  }

  return {
    handleIgnoreEvidence,
    handleDeleteEvidence,
    handleRetireEvidence,
    handleReacquireEvidence,
    handleUnsealEvidence,
  }
}
