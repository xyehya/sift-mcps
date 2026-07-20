import { postCustodyResolve } from '@/api/endpoints'
import { runGuard } from '@/components/evidence/custody-guard'

// ─────────────────────────────────────────────────────────────────────────
// useResolveActions — the unified D4 Resolve flow. ONE password + ONE reason
// authorizes a batch of selected findings; each finding carries its own
// honest, distinct verb (IGNORE for a new pending entry, RETIRE for a missing
// or changed sealed object — Replace/Reacquire and exact Restore are
// permanently out of scope, so a changed object's only Resolve verb is
// Retire). Replaces the old per-verb ignore/retire/delete handlers.
// Mock/real split lives at the API adapter layer (AGENTS §3).
// ─────────────────────────────────────────────────────────────────────────

export function useResolveActions({
  refreshData,
  addToast,
  modalPassword,
  modalReason,
  sealIntentId,
  dispositions,
  setModalLoading,
  setModalError,
  setModalResult,
  afterSuccess,
}) {
  async function handleResolveFindings(e) {
    e.preventDefault()
    if (
      !runGuard({
        needReason: true,
        modalPassword,
        modalReason,
        setModalLoading,
        setModalError,
        setModalResult,
      })
    ) {
      return
    }
    const targets = dispositions ?? []
    if (targets.length === 0) {
      setModalError('Select at least one finding to resolve.')
      setModalLoading(false)
      return
    }
    try {
      const res = await postCustodyResolve({
        password: modalPassword,
        reason: modalReason,
        batch_key: sealIntentId,
        dispositions: targets.map(({ verb, target }) => ({ verb, target })),
      })
      const receipts = res.receipts ?? []
      setModalResult({ receipts })
      addToast(`Resolved ${receipts.length} finding${receipts.length === 1 ? '' : 's'}.`, 'success')
      afterSuccess(refreshData)
    } catch (err) {
      setModalError(err.message || 'Resolve failed')
    } finally {
      setModalLoading(false)
    }
  }

  return { handleResolveFindings }
}
