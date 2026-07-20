import { useEvidenceData } from '@/components/evidence/useEvidenceData'
import { useEvidenceActions } from '@/components/evidence/useEvidenceActions'

// ─────────────────────────────────────────────────────────────────────────
// useEvidenceCustody — STABLE public entry (§11). Composes the data-load hook
// (useEvidenceData: evidence list + chain status) and the action-handlers hook
// (useEvidenceActions: Add/Seal · Full Verify Evidence · the unified D4
// Resolve batch (Ignore/Retire) · anchor · proof-export · per-item verify)
// into the single combined surface EvidenceTab consumes. The split is
// structural (§7 hook ceiling). Keeps EvidenceTab a thin orchestrator.
// Mock/real split lives at the API adapter layer (AGENTS §3).
// ─────────────────────────────────────────────────────────────────────────

export function useEvidenceCustody({
  chainStatus,
  setChainStatus,
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
  const { evidence, setEvidence, evidenceLoading, evidenceError, refreshData } = useEvidenceData({
    setChainStatus,
  })

  const actions = useEvidenceActions({
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
  })

  return {
    evidence,
    evidenceLoading,
    evidenceError,
    refreshData,
    ...actions,
  }
}
