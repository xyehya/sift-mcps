import { useState, useEffect, useMemo } from 'react'
import { motion } from 'framer-motion'
import { Archive, ShieldCheck, ShieldOff, Database, Lock, RefreshCw, Key, FileCheck } from 'lucide-react'

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
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { evidenceSummary, custodyClass } from './evidence-utils'
import { EvidenceList } from './EvidenceList'
import { EvidenceDetail } from './EvidenceDetail'
import {
  HmacBar,
  CustodyViolations,
  UnregisteredFiles,
  RegisteredEvidenceTable,
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
// EvidenceTab — unified chain-of-custody registry + custody operations.
//
// LAYOUT (always rendered in both mock and live modes):
//   Header → chain-level action strip → stat tiles →
//   [ Registry master-detail (mock items or API items) ] →
//   Custody ops section (HMAC · write-block · Solana · violations · table) →
//   Modals
//
// DATA SOURCE (no UI split — only data and action execution differ):
//   mock mode  (portalState.evidence_items populated): registry from fixture
//              items; per-item actions do optimistic state update + honest
//              "prototype — auth pending" toast; chain-ops use API.
//   live mode  (evidence_items null/empty): registry from API getEvidence().
//              All actions use real endpoints.
//
// GUARDRAIL CONTRACTS (must remain byte-identical):
//   EvidenceUnseal.test.jsx — data-testid="unseal-btn-{ev.path}" lives in
//     RegisteredEvidenceTable (EvidenceCustodyOps.jsx); that component is
//     always rendered in the custody ops section below the registry, so the
//     testid is in DOM regardless of mock/live.
//   data-testid="unseal-submit" lives in UnsealModal (EvidenceCustodyModals.jsx).
//   useStore.interface.test.js — store public surface is frozen (additive only).
// ─────────────────────────────────────────────────────────────────────────

// ── Icon map (Tailwind JIT needs literal class keys) ────────────────────

const TILE_ICONS = {
  shield: ShieldCheck,
  shieldOff: ShieldOff,
  database: Database,
  lock: Lock,
  archive: Archive,
}

// ── Stat tile ────────────────────────────────────────────────────────────

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

// ── Per-item action bar (mock mode detail pane) ──────────────────────────
// Shows Verify · Seal / Unseal · Retire · Re-acquire per selected artifact.
// In mock mode all handlers are optimistic; live handlers are the real API.

function ItemActionBar({ item, isMock, chainStatus, onVerify, onOpenModal }) {
  if (!item) return null
  const isSealed = item.custody_status === 'sealed'
  const isUnsealed = item.custody_status === 'unsealed'
  const isPending = item.custody_status === 'pending'
  // Path used by API endpoints (mock items use their name as path proxy)
  const itemPath = item.path ?? item.name

  return (
    <div className="shrink-0 border-t border-border px-5 py-3">
      <p className="mono mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        Actions for {item.id ?? itemPath}
        {isMock && (
          <span className="ml-2 text-[9px] text-status-pending normal-case tracking-normal">
            prototype — auth pending
          </span>
        )}
      </p>
      <div className="flex flex-wrap gap-2">
        {/* Verify integrity */}
        <Button
          variant="outline"
          size="sm"
          className="mono h-7 px-2.5 text-[11px]"
          onClick={() => onVerify(itemPath)}
        >
          <FileCheck className="mr-1.5 size-3" aria-hidden />
          Verify
        </Button>

        {/* Seal (pending) */}
        {isPending && (
          <Button
            variant="outline"
            size="sm"
            className="mono h-7 px-2.5 text-[11px] text-status-approved border-status-approved/40 hover:bg-status-approved/10"
            onClick={() => onOpenModal('seal', itemPath)}
          >
            <ShieldCheck className="mr-1.5 size-3" aria-hidden />
            Seal
          </Button>
        )}

        {/* Unseal (sealed) */}
        {isSealed && (
          <Button
            variant="outline"
            size="sm"
            className="mono h-7 px-2.5 text-[11px] text-status-pending border-status-pending/40 hover:bg-status-pending/10"
            onClick={() => onOpenModal('unseal', itemPath)}
          >
            <ShieldOff className="mr-1.5 size-3" aria-hidden />
            Unseal
          </Button>
        )}

        {/* Re-acquire (unsealed / pending) */}
        {(isUnsealed || isPending) && (
          <Button
            variant="outline"
            size="sm"
            className="mono h-7 px-2.5 text-[11px]"
            onClick={() => onOpenModal('reacquire', itemPath)}
          >
            <RefreshCw className="mr-1.5 size-3" aria-hidden />
            Re-acquire
          </Button>
        )}

        {/* Retire (any status) */}
        <Button
          variant="outline"
          size="sm"
          className="mono h-7 px-2.5 text-[11px] text-muted-foreground hover:text-destructive hover:border-destructive"
          onClick={() => onOpenModal('retire', itemPath)}
        >
          Retire
        </Button>

        {/* Ignore (unregistered / pending) */}
        {isPending && (
          <Button
            variant="outline"
            size="sm"
            className="mono h-7 px-2.5 text-[11px] text-muted-foreground"
            onClick={() => onOpenModal('ignore', itemPath)}
          >
            Ignore
          </Button>
        )}
      </div>
    </div>
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

  // ── API-backed evidence list (live mode + RegisteredEvidenceTable) ────
  const [evidence, setEvidence] = useState([])
  const [evidenceLoading, setEvidenceLoading] = useState(true)
  const [evidenceError, setEvidenceError] = useState(null)
  const [unregisteredMetadata, setUnregisteredMetadata] = useState({})
  const [sortCol, setSortCol] = useState('path')
  const [sortAsc, setSortAsc] = useState(true)
  const [verifyStatus, setVerifyStatus] = useState({})

  // ── Mock registry items (from portalState.evidence_items) ────────────
  // portalState is populated by installMockData() → PORTAL_STATE.evidence_items.
  // Avoids a new top-level store key (store surface frozen).
  const mockItems = useMemo(() => portalState?.evidence_items ?? [], [portalState])
  const isMock = mockItems.length > 0

  // Registry display list: mock items take precedence; fall back to API evidence.
  const displayItems = isMock ? mockItems : evidence

  const [selectedEvidenceId, setSelectedEvidenceId] = useState(null)

  // Auto-select first item when items arrive
  useEffect(() => {
    if (displayItems.length > 0 && !selectedEvidenceId) {
      setSelectedEvidenceId(displayItems[0].id ?? displayItems[0].path)
    }
  }, [displayItems.length]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Modal state ───────────────────────────────────────────────────────
  // activeModal ∈ 'verify_hmac'|'seal'|'ignore'|'delete'|'retire'|'reacquire'|'unseal'|null
  const [activeModal, setActiveModal] = useState(null)
  const [pendingPath, setPendingPath] = useState(null)
  const [modalPassword, setModalPassword] = useState('')
  const [modalReason, setModalReason] = useState('')
  const [modalLoading, setModalLoading] = useState(false)
  const [modalError, setModalError] = useState('')
  const [modalResult, setModalResult] = useState(null)

  // ── Mock item optimistic state (mock mode per-item actions) ──────────
  const [mockItemOverrides, setMockItemOverrides] = useState({})

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

  useEffect(() => { refreshData() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Modal helpers ────────────────────────────────────────────────────

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

  // ── Mock-mode per-item optimistic handlers ───────────────────────────
  // Accept any non-empty password; show honest "prototype — auth pending" wording.
  // TODO(CG-AUTH): replace with real endpoint calls when live auth is wired.

  function mockOptimisticAction(action, path, extraToast) {
    if (!modalPassword) { setModalError('Password required.'); return false }
    if (action === 'ignore' || action === 'retire' || action === 'reacquire' || action === 'delete') {
      if (!modalReason) { setModalError('Reason is required.'); return false }
    }
    setModalLoading(true)
    setModalError('')
    // Simulate async; prototype — auth pending
    setTimeout(() => {
      setModalResult({ success: true })
      addToast(extraToast + ' (prototype — auth pending)', 'success')
      if (path) {
        const overrides = {}
        if (action === 'seal') overrides.custody_status = 'sealed'
        else if (action === 'unseal') overrides.custody_status = 'unsealed'
        else if (action === 'retire') overrides.custody_status = 'retired'
        if (Object.keys(overrides).length) {
          setMockItemOverrides((prev) => ({ ...prev, [path]: { ...prev[path], ...overrides } }))
        }
      }
      setModalLoading(false)
      setTimeout(() => { closeModal() }, 1200)
    }, 600)
    return true
  }

  // ── Live custody action handlers ─────────────────────────────────────

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

  async function handleVerifyHmac(e) {
    e.preventDefault()
    if (isMock) { mockOptimisticAction('verify_hmac', null, 'HMAC chain verified'); return }
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
    if (isMock && pendingPath) {
      mockOptimisticAction('seal', pendingPath, `${pendingPath} sealed`)
      return
    }
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
    if (isMock) { mockOptimisticAction('ignore', pendingPath, 'File ignored'); return }
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
    if (isMock) { mockOptimisticAction('delete', pendingPath, 'File deleted'); return }
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
    if (isMock) { mockOptimisticAction('retire', pendingPath, 'File retired'); return }
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
    if (isMock) { mockOptimisticAction('reacquire', pendingPath, 'Evidence re-acquired'); return }
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
    if (isMock) {
      setVerifyStatus((prev) => ({ ...prev, [path]: 'checking' }))
      setTimeout(() => {
        setVerifyStatus((prev) => ({ ...prev, [path]: 'verified' }))
        addToast(`${path} integrity verified (prototype — auth pending)`, 'success')
      }, 800)
      return
    }
    setVerifyStatus((prev) => ({ ...prev, [path]: 'checking' }))
    try {
      const result = await postVerifyEvidence(path)
      setVerifyStatus((prev) => ({
        ...prev,
        [path]: result.status === 'verified' ? 'verified' : result.status === 'failed' ? 'failed' : (result.status || 'unknown'),
      }))
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

  // ── Stat tile derivation ──────────────────────────────────────────────
  // Mock items are the source of truth for sealed/total in mock mode.
  // Live: fall back to chainStatus / portalState.evidence.
  const mockSummary = isMock ? evidenceSummary(mockItems) : null
  const sealedCount = mockSummary?.sealed ?? portalState?.evidence?.sealed ?? chainStatus?.ok?.length ?? 0
  const totalCount = mockSummary?.total ?? portalState?.evidence?.total ?? evidence.length
  const manifestVersion = chainStatus?.manifest_version
  const writeProtected = chainStatus?.write_protected
  const hmacNeeded = chainStatus?.hmac_verify_needed

  // Effective mock items with in-session optimistic overrides applied
  const effectiveMockItems = isMock
    ? mockItems.map((item) => {
        const ov = mockItemOverrides[item.name]
        return ov ? { ...item, ...ov } : item
      })
    : []

  const selectedItem = isMock
    ? effectiveMockItems.find((i) => i.id === selectedEvidenceId) ?? null
    : null

  return (
    <div
      className="flex flex-col overflow-hidden"
      style={{ height: 'calc(100vh - 86px)' }}
    >
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="shrink-0 px-5 pt-5 pb-2">
        <div className="flex items-start justify-between gap-4">
          <div>
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
          {/* Chain-level action buttons (always visible) */}
          <div className="flex items-center gap-2 pt-0.5">
            <Button
              variant="outline"
              size="sm"
              className="mono h-7 px-2.5 text-[11px]"
              onClick={() => openModal('verify_hmac')}
              title="Verify HMAC chain (password required)"
            >
              <Key className="mr-1.5 size-3" aria-hidden />
              Verify HMAC
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="mono h-7 px-2.5 text-[11px]"
              onClick={() => openModal('seal')}
              title="Seal evidence manifest (password required)"
            >
              <ShieldCheck className="mr-1.5 size-3 text-status-approved" aria-hidden />
              Seal Manifest
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="mono h-7 px-2.5 text-[11px] text-muted-foreground"
              onClick={handleRescan}
              title="Rescan evidence directory"
            >
              <RefreshCw className="mr-1.5 size-3" aria-hidden />
              Rescan
            </Button>
          </div>
        </div>

        {/* Write-protect case-level indicator (one place, not per file) */}
        {chainStatus != null && (
          <div className={cn(
            'mt-2 inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-semibold',
            writeProtected
              ? 'border-status-approved/40 bg-status-approved/10 text-status-approved'
              : writeProtected === false
                ? 'border-status-pending/40 bg-status-pending/10 text-status-pending'
                : 'border-border bg-secondary text-muted-foreground',
          )}>
            <Lock className="size-2.5" aria-hidden />
            Write-protect: {writeProtected ? 'On (case folder mounted read-only)' : writeProtected === false ? 'Off — not write-blocked' : '—'}
          </div>
        )}
      </div>

      {/* ── Stat tiles ──────────────────────────────────────────────── */}
      <div className="shrink-0 px-5 py-3">
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
            foot={sealedCount === totalCount && totalCount > 0 ? 'Full custody' : `${totalCount - sealedCount} not sealed`}
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

      {/* ── Body: scrollable (all sections always rendered) ─────────── */}
      <div className="min-h-0 flex-1 overflow-y-auto">

        {/* Registry master-detail — rendered only in mock/dev mode.
            In live mode, the RegisteredEvidenceTable in the custody ops
            section below serves as the evidence registry (with Unseal/Verify
            per-row actions). This avoids duplicate ev.path text in DOM, which
            would break findByText in EvidenceUnseal.test.jsx (multi-match). */}
        {isMock && (
          <div
            className="border-b border-border"
            style={{ height: '380px', display: 'flex' }}
          >
            {/* List pane */}
            <div className="w-5/12 min-w-0 overflow-hidden border-r border-border">
              <EvidenceList
                items={effectiveMockItems}
                selectedId={selectedEvidenceId}
                onSelect={setSelectedEvidenceId}
                loading={false}
              />
            </div>

            {/* Detail pane + per-item action bar */}
            <div className="flex w-7/12 min-w-0 flex-col overflow-hidden">
              <EvidenceDetail item={selectedItem} />
              <ItemActionBar
                item={selectedItem}
                isMock={isMock}
                chainStatus={chainStatus}
                onVerify={handleVerifyEvidence}
                onOpenModal={openModal}
              />
            </div>
          </div>
        )}

        {/* Chain-of-custody operations section — always rendered (satisfies test data-testid contract) */}
        <div className="space-y-4 px-5 py-5">
          <p className="mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            Chain of custody operations
          </p>

          <HmacBar
            chainStatus={chainStatus}
            onVerifyClick={() => openModal('verify_hmac')}
          />

          {/* Write-block + Solana (case-level custody infrastructure) */}
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

          {/* Registered evidence table (API-backed). Always rendered — this
              is the guaranteed location of data-testid="unseal-btn-{path}"
              which the EvidenceUnseal.test.jsx guardrail suite relies on.
              In mock mode it will show empty/loading; in live mode it shows
              the registered file list with per-row Unseal / Verify buttons. */}
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
              <Button
                variant="outline"
                size="sm"
                className="mono mt-3 h-7 px-2.5 text-[10px]"
                onClick={handleProofExport}
              >
                Generate Proof Export
              </Button>
            </div>
          )}
        </div>
      </div>

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
