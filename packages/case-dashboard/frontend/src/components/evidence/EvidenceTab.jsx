import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'

import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants } from '@/lib/motion'
import { sortEvidence } from '@/components/evidence/evidence-utils'
import { useEvidenceCustody } from '@/components/evidence/useEvidenceCustody'
import { EvidenceHeader } from '@/components/evidence/EvidenceHeader'
import { HmacBar } from '@/components/evidence/HmacBar'
import { CustodyStatusGrid } from '@/components/evidence/CustodyStatusGrid'
import { CustodyViolations } from '@/components/evidence/CustodyViolations'
import { UnregisteredFiles } from '@/components/evidence/UnregisteredFiles'
import { RegisteredEvidenceTable } from '@/components/evidence/RegisteredEvidenceTable'
import { EvidenceModals } from '@/components/evidence/EvidenceModals'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceTab — chain-of-custody dashboard (Mission Control reskin of the
// legacy single-column custody view). ONE primary scroll owner; no master-
// detail. Top→bottom IA: Header → HMAC bar → custody status grid (write-block ·
// Solana · proof-export) → custody violations → unregistered files →
// registered-evidence table → modals. Reskinned to orange tokens, lucide icons,
// framer-motion, shadcn primitives, ≤400-line decomposed files.
//
// FROZEN CONTRACTS (must remain byte-identical / green):
//   EvidenceUnseal.test.jsx — data-testid="unseal-btn-{ev.path}" (gated on
//     chainStatus.ok membership) in RegisteredEvidenceTable;
//     data-testid="unseal-submit" in the unseal modal (EvidenceModals).
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

  // Modal state — activeModal ∈ verify_hmac|seal|ignore|delete|retire|reacquire|unseal|null
  const [activeModal, setActiveModal] = useState(null)
  const [pendingPath, setPendingPath] = useState(null)
  const [modalPassword, setModalPassword] = useState('')
  const [modalReason, setModalReason] = useState('')
  const [modalLoading, setModalLoading] = useState(false)
  const [modalError, setModalError] = useState('')
  const [modalResult, setModalResult] = useState(null)

  function openModal(name, path = null) {
    setActiveModal(name)
    setPendingPath(path)
    setModalPassword('')
    setModalReason('')
    setModalError('')
    setModalResult(null)
  }

  function closeModal() {
    setActiveModal(null)
    setPendingPath(null)
    setModalPassword('')
    setModalReason('')
    setModalError('')
    setModalResult(null)
  }

  // Close + refresh after a successful custody action (1.5s success-state dwell).
  function afterSuccess(refreshData, delayMs = 1500) {
    setTimeout(() => {
      closeModal()
      refreshData()
    }, delayMs)
  }

  const custody = useEvidenceCustody({
    chainStatus,
    setChainStatus,
    addToast,
    modalPassword,
    modalReason,
    pendingPath,
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
        <EvidenceHeader chainStatus={chainStatus} onRescan={custody.handleRescan} />

        <HmacBar chainStatus={chainStatus} onVerifyClick={() => openModal('verify_hmac')} />

        <CustodyStatusGrid
          chainStatus={chainStatus}
          onAnchor={custody.handleTriggerAnchor}
          onProofExport={custody.handleProofExport}
        />

        <CustodyViolations
          chainStatus={chainStatus}
          onRetire={(path) => openModal('retire', path)}
          onReacquire={(path) => openModal('reacquire', path)}
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
          onIgnore={(path) => openModal('ignore', path)}
          onDelete={(path) => openModal('delete', path)}
          onSeal={() => openModal('seal')}
        />

        <RegisteredEvidenceTable
          evidence={sortedEvidence}
          evidenceLoading={custody.evidenceLoading}
          evidenceError={custody.evidenceError}
          chainStatus={chainStatus}
          verifyStatus={custody.verifyStatus}
          sortCol={sortCol}
          sortAsc={sortAsc}
          onSort={handleSort}
          onUnseal={(path) => openModal('unseal', path)}
          onVerify={custody.handleVerifyEvidence}
          onRescan={custody.handleRescan}
          onNavigateFinding={(rid) => {
            setSelectedFindingId(rid)
            setFindingsFilter('all')
            setActiveTab('findings')
          }}
        />
      </motion.section>

      <EvidenceModals
        activeModal={activeModal}
        pendingPath={pendingPath}
        password={modalPassword}
        reason={modalReason}
        loading={modalLoading}
        error={modalError}
        result={modalResult}
        handlers={{
          onPasswordChange: setModalPassword,
          onReasonChange: setModalReason,
          onClose: closeModal,
          onVerifyHmac: custody.handleVerifyHmac,
          onSeal: custody.handleSealEvidence,
          onIgnore: custody.handleIgnoreEvidence,
          onDelete: custody.handleDeleteEvidence,
          onRetire: custody.handleRetireEvidence,
          onReacquire: custody.handleReacquireEvidence,
          onUnseal: custody.handleUnsealEvidence,
        }}
      />
    </div>
  )
}
