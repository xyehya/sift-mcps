import {
  postChainIgnore,
  postChainDelete,
  postChainRetire,
  postReplaceBegin,
  postRestoreBegin,
  postRecoveryComplete,
} from '@/api/endpoints'

import { runGuard } from '@/components/evidence/custody-guard'

// ─────────────────────────────────────────────────────────────────────────
// useCustodyLedgerActions — the password + reason-guarded LEDGERED custody
// mutations: ignore · delete · retire · replace/restore begin and completion. Each re-auths with
// runGuard (reason required), then on success records via afterSuccess(
// refreshData). Mock/real split is at the API adapter layer (AGENTS §3).
// ─────────────────────────────────────────────────────────────────────────

export function useCustodyLedgerActions({
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

  async function beginRecovery(e, endpoint, label) {
    e.preventDefault()
    if (!guard(true)) return
    try {
      const res = await endpoint({
        password: modalPassword,
        path: pendingPath,
        reason: modalReason,
        idempotency_key: sealIntentId,
      })
      if (res.ready_for_replacement && res.operation_id) {
        addToast(`${label} authorized. Custody gate is blocked until completion.`, 'success')
        setModalResult({ success: true })
        afterSuccess(refreshData)
      } else {
        throw new Error(res.error || `${label} begin failed`)
      }
    } catch (err) {
      setModalError(err.message || `${label} begin failed`)
    } finally {
      setModalLoading(false)
    }
  }

  const handleReplaceBegin = (e) => beginRecovery(e, postReplaceBegin, 'Replace/Reacquire')
  const handleRestoreBegin = (e) => beginRecovery(e, postRestoreBegin, 'Exact Restore')

  async function handleRecoveryComplete(e) {
    e.preventDefault()
    if (!guard(false)) return
    try {
      const res = await postRecoveryComplete({ password: modalPassword, operation_id: pendingPath })
      if (res.completed && (res.reacquired || res.restored_exact)) {
        addToast(res.restored_exact ? 'Original evidence bytes restored exactly.' : 'Replacement sealed as a new evidence version.', 'success')
        setModalResult({ success: true })
        afterSuccess(refreshData)
      } else {
        throw new Error(res.error || 'Recovery completion failed')
      }
    } catch (err) {
      setModalError(err.message || 'Recovery completion failed')
    } finally {
      setModalLoading(false)
    }
  }

  return {
    handleIgnoreEvidence,
    handleDeleteEvidence,
    handleRetireEvidence,
    handleReplaceBegin,
    handleRestoreBegin,
    handleRecoveryComplete,
  }
}
