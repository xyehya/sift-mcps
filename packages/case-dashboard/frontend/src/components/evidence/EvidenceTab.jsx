import { useState, useEffect, useMemo } from 'react'
import { motion } from 'framer-motion'
import { Archive, ShieldCheck, ShieldOff, Database, Lock } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants } from '@/lib/motion'
import {
  getEvidence,
  getChainStatus,
  postChainRescan,
  postChainSeal,
  postChainAnchor,
  postChainProofExport,
  postChainVerifyHmac,
  postVerifyEvidence,
  postChainIgnore,
  postChainDelete,
  postChainRetire,
  postChainReacquire,
  unsealEvidence,
} from '@/api/endpoints'
import { Card } from '@/components/ui/card'
import { evidenceSummary } from './evidence-utils'
import { EvidenceList } from './EvidenceList'
import { EvidenceDetail } from './EvidenceDetail'
import {
  HmacBar,
  CustodyViolations,
  UnregisteredFiles,
  RegisteredEvidenceTable,
  RescanBar,
  WriteBlockCard,
  SolanaCard,
} from './EvidenceCustodyOps'
import {
  VerifyHmacModal,
  SealModal,
  IgnoreModal,
  DeleteModal,
  RetireModal,
  ReacquireModal,
  UnsealModal,
} from './EvidenceCustodyModals'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceTab — chain-of-custody registry for the SIFT investigaton portal.
// Header: H1 "Evidence" + muted subtitle.
// Stat tiles: Sealed X/total · Manifest version · Write-protect · Integrity.
// Registry: master-detail list of acquired artifacts (mock in dev, API in prod).
// Custody section: HMAC reminder · write-block · Solana anchor ·
//   unregistered files · registered evidence table with Unseal/Verify.
//
// The EvidenceUnseal.test.jsx guardrail suite tests the per-item Unseal button
// (data-testid="unseal-btn-{path}") and modal (data-testid="unseal-submit") —
// those data-testids must remain in the rendered DOM tree.
// ─────────────────────────────────────────────────────────────────────────

// ── Stat tiles ──────────────────────────────────────────────────────────

const TILE_ICONS = {
  shield: ShieldCheck,
  shieldOff: ShieldOff,
  database: Database,
  lock: Lock,
  archive: Archive,
}

function StatTile({ icon: iconKey, label, value, sub, tone, foot, variants }) {
  const Icon = TILE_ICONS[iconKey] ?? Archive
  return (
    <motion.div variants={variants.staggerItem}>
      <Card className="p-4 gap-2">
        <div className="flex items-center justify-between">
          <span className="mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            {label}
          </span>
          <Icon className={cn('size-4', tone)} aria-hidden />
        </div>
        <div className="flex items-baseline gap-1">
          <span className="tnum font-display text-[26px] font-bold leading-none text-foreground">
            {value}
          </span>
          {sub && <span className="mono text-xs text-muted-foreground">{sub}</span>}
        </div>
        {foot && <div className={cn('text-[11px]', tone)}>{foot}</div>}
      </Card>
    </motion.div>
  )
}

// ── Main tab ─────────────────────────────────────────────────────────────

export function EvidenceTab() {
  const {
    chainStatus,
    setChainStatus,
    addToast,
    setActiveTab,
    setSelectedFindingId,
    setFindingsFilter,
    portalState,
  } = useStoreSlice((state) => ({
    chainStatus: state.chainStatus,
    setChainStatus: state.setChainStatus,
    addToast: state.addToast,
    setActiveTab: state.setActiveTab,
    setSelectedFindingId: state.setSelectedFindingId,
    setFindingsFilter: state.setFindingsFilter,
    portalState: state.portalState,
  }))

  const variants = useMotionVariants()

  // ── API-backed evidence list (for chain-of-custody ops) ──────────────
  const [evidence, setEvidence] = useState([])
  const [evidenceLoading, setEvidenceLoading] = useState(true)
  const [evidenceError, setEvidenceError] = useState(null)
  const [unregisteredMetadata, setUnregisteredMetadata] = useState({})
  const [sortCol, setSortCol] = useState('path')
  const [sortAsc, setSortAsc] = useState(true)
  const [verifyStatus, setVerifyStatus] = useState({})

  // ── Evidence registry items (from portalState.evidence_items in mock mode) ──
  // portalState is populated by installMockData() → PORTAL_STATE.evidence_items;
  // this avoids a new top-level store key (store surface is frozen).
  const mockItems = useMemo(() => portalState?.evidence_items ?? [], [portalState])
  const [selectedEvidenceId, setSelectedEvidenceId] = useState(null)

  // Auto-select first item when mock items arrive
  useEffect(() => {
    if (mockItems.length > 0 && !selectedEvidenceId) {
      setSelectedEvidenceId(mockItems[0].id)
    }
  }, [mockItems, selectedEvidenceId])

  // ── Modal state ───────────────────────────────────────────────────────
  // activeModal ∈ 'verify_hmac'|'seal'|'ignore'|'delete'|'retire'|'reacquire'|'unseal'|null
  const [activeModal, setActiveModal] = useState(null)
  const [pendingPath, setPendingPath] = useState(null)
  const [modalPassword, setModalPassword] = useState('')
  const [modalReason, setModalReason] = useState('')
  const [modalLoading, setModalLoading] = useState(false)
  const [modalError, setModalError] = useState('')
  const [modalResult, setModalResult] = useState(null)

  async function refreshData() {
    setEvidenceLoading(true)
    setEvidenceError(null)
    try {
      const ev = await getEvidence()
      setEvidence(ev || [])
    } catch (e) {
      setEvidenceError(e.message || 'Failed to load evidence list')
    } finally {
      setEvidenceLoading(false)
    }
    try {
      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)
    } catch (e) {
      console.error('Failed to load chain status', e)
    }
  }

  useEffect(() => { refreshData() }, [])

  // ── Custody action handlers ──────────────────────────────────────────

  async function handleRescan() {
    try {
      addToast('Rescanning evidence directory…', 'info')
      const freshStatus = await postChainRescan()
      if (freshStatus) setChainStatus(freshStatus)
      const ev = await getEvidence()
      setEvidence(ev || [])
      addToast('Evidence chain rescan completed', 'success')
    } catch (ex) {
      addToast(ex.message || 'Rescan failed', 'error')
    }
  }

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

  function afterSuccess(delayMs = 1500) {
    setTimeout(() => {
      closeModal()
      refreshData()
    }, delayMs)
  }

  async function handleVerifyHmac(e) {
    e.preventDefault()
    if (!modalPassword) { setModalError('Password required.'); return }
    setModalLoading(true); setModalError(''); setModalResult(null)
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
    if (!modalPassword) { setModalError('Password required.'); return }
    setModalLoading(true); setModalError(''); setModalResult(null)
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
        afterSuccess()
      } else {
        throw new Error(res.error || 'Seal failed')
      }
    } catch (err) {
      setModalError(err.message || 'Seal failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleIgnoreEvidence(e) {
    e.preventDefault()
    if (!modalReason) { setModalError('Reason is required.'); return }
    if (!modalPassword) { setModalError('Password required.'); return }
    setModalLoading(true); setModalError(''); setModalResult(null)
    try {
      const res = await postChainIgnore({ password: modalPassword, path: pendingPath, reason: modalReason })
      if (res.ignored) {
        addToast('File marked as ignored successfully!', 'success')
        setModalResult({ success: true })
        afterSuccess()
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
    if (!modalReason) { setModalError('Reason is required.'); return }
    if (!modalPassword) { setModalError('Password required.'); return }
    setModalLoading(true); setModalError(''); setModalResult(null)
    try {
      const res = await postChainDelete({ password: modalPassword, path: pendingPath, reason: modalReason })
      if (res.deleted) {
        addToast(res.file_removed ? 'File permanently deleted.' : 'Stray record removed.', 'success')
        setModalResult({ success: true })
        afterSuccess()
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
    if (!modalReason) { setModalError('Reason is required.'); return }
    if (!modalPassword) { setModalError('Password required.'); return }
    setModalLoading(true); setModalError(''); setModalResult(null)
    try {
      const res = await postChainRetire({ password: modalPassword, path: pendingPath, reason: modalReason })
      if (res.ignored || res.retired || res.manifest_version !== undefined) {
        addToast('File retired successfully!', 'success')
        setModalResult({ success: true })
        afterSuccess()
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
    if (!modalReason) { setModalError('Reason is required.'); return }
    if (!modalPassword) { setModalError('Password required.'); return }
    setModalLoading(true); setModalError(''); setModalResult(null)
    try {
      const res = await postChainReacquire({ password: modalPassword, path: pendingPath, reason: modalReason })
      if (res.reacquired) {
        addToast(`Evidence re-acquired and re-sealed (manifest v${res.manifest_version}).`, 'success')
        setModalResult({ success: true })
        afterSuccess()
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
    if (!modalReason) { setModalError('Reason is required.'); return }
    if (!modalPassword) { setModalError('Password required.'); return }
    setModalLoading(true); setModalError(''); setModalResult(null)
    try {
      // CL3a (B-MVP-017): password re-verified against Supabase server-side.
      const res = await unsealEvidence(pendingPath, modalReason, modalPassword)
      if (res.unsealed) {
        addToast('Evidence unsealed — immutability cleared. Re-seal before agent tools can run.', 'success')
        setModalResult({ success: true })
        afterSuccess()
      } else {
        throw new Error(res.error || 'Unseal failed')
      }
    } catch (err) {
      setModalError(err.message || 'Unseal failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleTriggerAnchor() {
    try {
      addToast('Submitting Solana anchor transaction…', 'info')
      const result = await postChainAnchor()
      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)
      if (result.anchored) {
        addToast('Manifest anchored successfully!', 'success')
      } else {
        addToast('Anchor submitted but not yet confirmed.', 'warning')
      }
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
      if (pe.verified) {
        addToast('Proof export generated and verified.', 'success')
      } else {
        addToast('Proof export recorded, but verification reported issues.', 'warning')
      }
    } catch (err) {
      addToast(err.message || 'Proof export failed', 'error')
    }
  }

  async function handleVerifyEvidence(path) {
    setVerifyStatus((prev) => ({ ...prev, [path]: 'checking' }))
    try {
      const result = await postVerifyEvidence(path)
      setVerifyStatus((prev) => ({ ...prev, [path]: result.status === 'verified' ? 'verified' : result.status === 'failed' ? 'failed' : (result.status || 'unknown') }))
    } catch {
      setVerifyStatus((prev) => ({ ...prev, [path]: 'error' }))
    }
  }

  const sortedEvidence = useMemo(() => {
    return [...evidence].sort((a, b) => {
      const av = a[sortCol] ?? ''
      const bv = b[sortCol] ?? ''
      const cmp = typeof av === 'number' && typeof bv === 'number'
        ? av - bv
        : String(av).localeCompare(String(bv))
      return sortAsc ? cmp : -cmp
    })
  }, [evidence, sortCol, sortAsc])

  // ── Stat tile derivation ─────────────────────────────────────────────
  // Prefer mock items when available (dev/visual mode), else derive from chainStatus + portalState
  const evidItems = mockItems.length > 0 ? mockItems : []
  const mockSummary = evidItems.length > 0 ? evidenceSummary(evidItems) : null
  const sealedCount = mockSummary?.sealed ?? portalState?.evidence?.sealed ?? chainStatus?.ok?.length ?? 0
  const totalCount = mockSummary?.total ?? portalState?.evidence?.total ?? evidence.length
  const manifestVersion = chainStatus?.manifest_version
  const writeProtected = chainStatus?.write_protected
  const hmacNeeded = chainStatus?.hmac_verify_needed

  const selectedItem = mockItems.find((i) => i.id === selectedEvidenceId) ?? null

  return (
    <div
      className="flex flex-col overflow-hidden"
      style={{ height: 'calc(100vh - 86px)' }}
    >
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="shrink-0 px-5 pt-5 pb-3">
        <h1
          className="font-display font-bold leading-none"
          style={{ fontSize: '24px', letterSpacing: '-.4px', color: 'var(--text-bright)' }}
        >
          Evidence
        </h1>
        <p className="mono mt-1.5 text-xs text-muted-foreground">
          Acquired artifacts · chain of custody · seal status
        </p>
      </div>

      {/* ── Stat tiles ──────────────────────────────────────────────── */}
      <div className="shrink-0 px-5 pb-4">
        <motion.div
          variants={variants.staggerContainer}
          initial="hidden"
          animate="show"
          className="grid gap-3"
          style={{ gridTemplateColumns: 'repeat(4,1fr)' }}
        >
          <StatTile
            icon={sealedCount === totalCount && totalCount > 0 ? 'shield' : 'shieldOff'}
            label="Sealed"
            value={`${sealedCount}/${totalCount}`}
            tone={sealedCount === totalCount && totalCount > 0 ? 'text-status-approved' : 'text-status-pending'}
            foot={sealedCount === totalCount && totalCount > 0 ? 'Full custody' : `${totalCount - sealedCount} unsealed`}
            variants={variants}
          />
          <StatTile
            icon="database"
            label="Manifest"
            value={manifestVersion != null && manifestVersion > 0 ? `v${manifestVersion}` : '—'}
            tone={manifestVersion > 0 ? 'text-status-approved' : 'text-muted-foreground'}
            foot={manifestVersion > 0 ? 'Sealed manifest' : 'Not yet sealed'}
            variants={variants}
          />
          <StatTile
            icon="lock"
            label="Write-protect"
            value={writeProtected == null ? '—' : writeProtected ? 'On' : 'Off'}
            tone={writeProtected ? 'text-status-approved' : writeProtected === false ? 'text-status-pending' : 'text-muted-foreground'}
            foot={writeProtected ? 'Mounted read-only' : writeProtected === false ? 'Not write-blocked' : 'Unknown'}
            variants={variants}
          />
          <StatTile
            icon={hmacNeeded === false ? 'shield' : hmacNeeded ? 'shieldOff' : 'archive'}
            label="Integrity"
            value={hmacNeeded === false ? 'Verified' : hmacNeeded ? 'Pending' : '—'}
            tone={hmacNeeded === false ? 'text-status-approved' : hmacNeeded ? 'text-status-pending' : 'text-muted-foreground'}
            foot={hmacNeeded === false ? 'HMAC chain intact' : hmacNeeded ? 'Re-hash needed' : 'Not checked'}
            variants={variants}
          />
        </motion.div>
      </div>

      {/* ── Main body: registry (if mock items) OR custody ops ──────── */}
      {mockItems.length > 0 ? (
        /* Dev/mock mode: show the artifact registry as master-detail */
        <div
          className="min-h-0 flex-1 overflow-hidden"
          style={{ display: 'grid', gridTemplateColumns: 'minmax(0,5fr) minmax(0,7fr)' }}
        >
          <EvidenceList
            items={mockItems}
            selectedId={selectedEvidenceId}
            onSelect={setSelectedEvidenceId}
            loading={false}
          />
          <EvidenceDetail item={selectedItem} />
        </div>
      ) : (
        /* Live mode: operational chain-of-custody panel */
        <div className="min-h-0 flex-1 overflow-y-auto px-5 pb-6 space-y-4">
          <RescanBar onRescan={handleRescan} />

          <HmacBar
            chainStatus={chainStatus}
            onVerifyClick={() => openModal('verify_hmac')}
          />

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                Write Block Status
              </p>
              <WriteBlockCard chainStatus={chainStatus} />
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                Solana Anchor Status
              </p>
              <SolanaCard chainStatus={chainStatus} onAnchor={handleTriggerAnchor} />
            </div>
          </div>

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
            evidenceLoading={evidenceLoading}
            evidenceError={evidenceError}
            chainStatus={chainStatus}
            verifyStatus={verifyStatus}
            sortCol={sortCol}
            sortAsc={sortAsc}
            onSort={(col) => {
              if (col === sortCol) setSortAsc((v) => !v)
              else { setSortCol(col); setSortAsc(true) }
            }}
            onUnseal={(path) => openModal('unseal', path)}
            onVerify={handleVerifyEvidence}
            onNavigateFinding={(rid) => {
              setSelectedFindingId(rid)
              setFindingsFilter('all')
              setActiveTab('findings')
            }}
          />

          {/* Proof export (DB authority only) */}
          {chainStatus?.authority === 'db' && (
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                Custody Proof Export
              </p>
              {chainStatus.proof_export ? (
                <div className="text-xs">
                  <div
                    className={cn('mono text-[11px] font-semibold', chainStatus.proof_export.verified ? 'text-status-approved' : 'text-status-pending')}
                  >
                    {chainStatus.proof_export.verified ? 'Verified against mounted evidence' : 'Recorded — verification reported issues'}
                  </div>
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">No proof export recorded yet.</p>
              )}
              <button
                type="button"
                onClick={handleProofExport}
                className="mono mt-3 rounded-lg border border-border bg-secondary px-2 py-1 text-[10px] font-semibold text-foreground transition-colors hover:bg-card focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                Generate Proof Export
              </button>
            </div>
          )}
        </div>
      )}

      {/* ── Modals (chain-of-custody actions) ──────────────────────── */}
      {activeModal === 'verify_hmac' && (
        <VerifyHmacModal
          password={modalPassword}
          onPasswordChange={setModalPassword}
          loading={modalLoading}
          error={modalError}
          result={modalResult}
          onClose={closeModal}
          onSubmit={handleVerifyHmac}
        />
      )}
      {activeModal === 'seal' && (
        <SealModal
          password={modalPassword}
          onPasswordChange={setModalPassword}
          loading={modalLoading}
          error={modalError}
          result={modalResult}
          onClose={closeModal}
          onSubmit={handleSealEvidence}
        />
      )}
      {activeModal === 'ignore' && (
        <IgnoreModal
          path={pendingPath}
          password={modalPassword}
          onPasswordChange={setModalPassword}
          reason={modalReason}
          onReasonChange={setModalReason}
          loading={modalLoading}
          error={modalError}
          result={modalResult}
          onClose={closeModal}
          onSubmit={handleIgnoreEvidence}
        />
      )}
      {activeModal === 'delete' && (
        <DeleteModal
          path={pendingPath}
          password={modalPassword}
          onPasswordChange={setModalPassword}
          reason={modalReason}
          onReasonChange={setModalReason}
          loading={modalLoading}
          error={modalError}
          result={modalResult}
          onClose={closeModal}
          onSubmit={handleDeleteEvidence}
        />
      )}
      {activeModal === 'retire' && (
        <RetireModal
          path={pendingPath}
          password={modalPassword}
          onPasswordChange={setModalPassword}
          reason={modalReason}
          onReasonChange={setModalReason}
          loading={modalLoading}
          error={modalError}
          result={modalResult}
          onClose={closeModal}
          onSubmit={handleRetireEvidence}
        />
      )}
      {activeModal === 'reacquire' && (
        <ReacquireModal
          path={pendingPath}
          password={modalPassword}
          onPasswordChange={setModalPassword}
          reason={modalReason}
          onReasonChange={setModalReason}
          loading={modalLoading}
          error={modalError}
          result={modalResult}
          onClose={closeModal}
          onSubmit={handleReacquireEvidence}
        />
      )}
      {activeModal === 'unseal' && (
        <UnsealModal
          path={pendingPath}
          password={modalPassword}
          onPasswordChange={setModalPassword}
          reason={modalReason}
          onReasonChange={setModalReason}
          loading={modalLoading}
          error={modalError}
          result={modalResult}
          onClose={closeModal}
          onSubmit={handleUnsealEvidence}
        />
      )}
    </div>
  )
}
