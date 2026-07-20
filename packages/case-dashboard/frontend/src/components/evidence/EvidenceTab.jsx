import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'

import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants } from '@/lib/motion'
import { Button } from '@/components/ui/button'
import { sortEvidence } from '@/components/evidence/evidence-utils'
import { useEvidenceCustody } from '@/components/evidence/useEvidenceCustody'
import { EvidenceHeader } from '@/components/evidence/EvidenceHeader'
import { FullVerifyBar } from '@/components/evidence/FullVerifyBar'
import { CustodyStatusGrid } from '@/components/evidence/CustodyStatusGrid'
import { CustodyViolations } from '@/components/evidence/CustodyViolations'
import { UnregisteredFiles } from '@/components/evidence/UnregisteredFiles'
import { SealedEvidenceTable } from '@/components/evidence/SealedEvidenceTable'
import { EvidenceModals } from '@/components/evidence/EvidenceModals'
import { IncompleteCustodyOperation } from '@/components/evidence/IncompleteCustodyOperation'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceTab — chain-of-custody dashboard (Mission Control reskin of the
// legacy single-column custody view). ONE primary scroll owner; no master-
// detail. Top→bottom IA: Header → full-verification bar → custody status grid
// (write-block · Solana · proof-export) → custody violations → unregistered
// files → registered-evidence table → modals. Reskinned to orange tokens,
// lucide icons, framer-motion, shadcn primitives, ≤400-line decomposed files.
//
// D4 — unified Resolve: CustodyViolations (missing/modified → Retire) and
// UnregisteredFiles (pending → Ignore) render a selection checkbox instead of
// a per-row action button; `resolveSelection` (target -> verb) is the shared
// batch, submitted through ONE password/reason Resolve modal. Replace/
// Reacquire, exact Restore, Delete Stray, storage-profile change, and
// signing-key rotation are permanently out of scope (SPEC) and have no UI
// here — see EVIDENCE-CUSTODY-SPEC.md "Out of Scope".
//
// FROZEN CONTRACTS (must remain green):
//   useStore.interface.test.js — store public surface frozen; this tab reads
//     chain/evidence via useStoreSlice only (no new top-level keys).
//
// Data-load + custody action handlers live in useEvidenceCustody (mock/real
// split is at the API adapter layer — no isMock branching here, AGENTS §3).
// ─────────────────────────────────────────────────────────────────────────

export function EvidenceTab() {
  const variants = useMotionVariants()

  const { chainStatus, setChainStatus, addToast, setActiveTab, setSelectedFindingId, setFindingsFilter } =
    useStoreSlice((state) => ({
      chainStatus: state.chainStatus,
      setChainStatus: state.setChainStatus,
      addToast: state.addToast,
      setActiveTab: state.setActiveTab,
      setSelectedFindingId: state.setSelectedFindingId,
      setFindingsFilter: state.setFindingsFilter,
    }))

  const [unregisteredMetadata, setUnregisteredMetadata] = useState({})
  const [sortCol, setSortCol] = useState('path')
  const [sortAsc, setSortAsc] = useState(true)

  // resolveSelection: { [target]: 'IGNORE' | 'RETIRE' } — the shared D4 batch
  // selection fed by CustodyViolations (Retire) and UnregisteredFiles (Ignore).
  const [resolveSelection, setResolveSelection] = useState({})
  const dispositions = useMemo(
    () => Object.entries(resolveSelection).map(([target, verb]) => ({ target, verb })),
    [resolveSelection],
  )

  function toggleResolveTarget(target, verb) {
    setResolveSelection((prev) => {
      if (prev[target]) {
        const next = { ...prev }
        delete next[target]
        return next
      }
      return { ...prev, [target]: verb }
    })
  }

  const [activeModal, setActiveModal] = useState(null)
  const [modalPassword, setModalPassword] = useState('')
  const [modalReason, setModalReason] = useState('')
  const [modalLoading, setModalLoading] = useState(false)
  const [modalError, setModalError] = useState('')
  const [modalResult, setModalResult] = useState(null)
  const [sealIntentId, setSealIntentId] = useState(null)

  function openModal(name) {
    setActiveModal(name)
    setModalPassword('')
    setModalReason('')
    setModalError('')
    setModalResult(null)
    setSealIntentId(['seal', 'resolve'].includes(name) ? crypto.randomUUID() : null)
  }

  function closeModal() {
    setActiveModal(null)
    setModalPassword('')
    setModalReason('')
    setModalError('')
    setModalResult(null)
    setSealIntentId(null)
  }

  // Close + refresh after a successful custody action (1.5s success-state dwell).
  function afterSuccess(refreshData, delayMs = 1500) {
    setTimeout(() => {
      closeModal()
      setResolveSelection({})
      refreshData()
    }, delayMs)
  }

  const custody = useEvidenceCustody({
    chainStatus,
    setChainStatus,
    addToast,
    modalPassword,
    modalReason,
    sealIntentId,
    pendingDispositions: dispositions,
    unregisteredMetadata,
    setModalLoading,
    setModalError,
    setModalResult,
    afterSuccess,
  })

  function handleSort(col) {
    if (col === sortCol) setSortAsc((v) => !v)
    else {
      setSortCol(col)
      setSortAsc(true)
    }
  }

  const sortedEvidence = useMemo(
    () => sortEvidence(custody.evidence, sortCol, sortAsc),
    [custody.evidence, sortCol, sortAsc],
  )

  return (
    <div className="h-full overflow-y-auto">
      <motion.section
        variants={variants.fadeRise}
        initial="hidden"
        animate="show"
        aria-label="Evidence chain of custody"
        className="mx-auto flex w-full max-w-6xl flex-col gap-4 p-5"
      >
        <EvidenceHeader chainStatus={chainStatus} onRefresh={custody.handleRefreshCustody} />

        <IncompleteCustodyOperation
          operation={chainStatus?.incomplete_operation}
          onResume={() => openModal('resume_seal')}
        />

        <FullVerifyBar chainStatus={chainStatus} onVerifyClick={() => openModal('full_verify')} />

        <CustodyStatusGrid
          chainStatus={chainStatus}
          onAnchor={custody.handleTriggerAnchor}
          onProofExport={custody.handleProofExport}
        />

        <CustodyViolations
          chainStatus={chainStatus}
          selectedTargets={new Set(Object.keys(resolveSelection).filter((t) => resolveSelection[t] === 'RETIRE'))}
          onToggleTarget={(path) => toggleResolveTarget(path, 'RETIRE')}
        />

        <UnregisteredFiles
          chainStatus={chainStatus}
          unregisteredMetadata={unregisteredMetadata}
          onMetaChange={(path, field, val) =>
            setUnregisteredMetadata((prev) => ({
              ...prev,
              [path]: { ...prev[path], [field]: val },
            }))
          }
          selectedTargets={new Set(Object.keys(resolveSelection).filter((t) => resolveSelection[t] === 'IGNORE'))}
          onToggleTarget={(path) => toggleResolveTarget(path, 'IGNORE')}
          onSeal={() => openModal('seal')}
        />

        {dispositions.length > 0 && (
          <div className="flex items-center justify-between rounded-lg border border-primary/40 bg-primary/5 p-3">
            <span className="mono text-xs font-semibold text-primary">
              {dispositions.length} finding{dispositions.length === 1 ? '' : 's'} selected
            </span>
            <Button type="button" size="sm" onClick={() => openModal('resolve')} className="text-xs font-semibold">
              Resolve Selected
            </Button>
          </div>
        )}

        <SealedEvidenceTable
          evidence={sortedEvidence}
          evidenceLoading={custody.evidenceLoading}
          evidenceError={custody.evidenceError}
          verifyStatus={custody.verifyStatus}
          sortCol={sortCol}
          sortAsc={sortAsc}
          onSort={handleSort}
          onVerify={custody.handleVerifyEvidence}
          onRefresh={custody.handleRefreshCustody}
          onNavigateFinding={(rid) => {
            setSelectedFindingId(rid)
            setFindingsFilter('all')
            setActiveTab('findings')
          }}
        />
      </motion.section>

      <EvidenceModals
        activeModal={activeModal}
        dispositions={dispositions}
        password={modalPassword}
        reason={modalReason}
        loading={modalLoading}
        error={modalError}
        result={modalResult}
        handlers={{
          onPasswordChange: setModalPassword,
          onReasonChange: setModalReason,
          onClose: closeModal,
          onFullVerifyEvidence: custody.handleFullVerifyEvidence,
          onSeal: custody.handleSealEvidence,
          onResumeSeal: custody.handleResumeSeal,
          onResolveFindings: custody.handleResolveFindings,
        }}
      />
    </div>
  )
}
