import { useState, useEffect, useMemo } from 'react'
import { useStore } from '../../store/useStore'
import {
  getEvidence,
  getChainStatus,
  postChainRescan,
  getChainChallenge,
  postChainSeal,
  postChainAnchor,
  postChainProofExport,
  postChainVerifyHmac,
  postVerifyEvidence,
  postChainIgnore,
  postChainDelete,
  postChainRetire
} from '../../api/endpoints'
import { computeSimpleChallengeResponse } from '../../api/crypto'
import { SkeletonBlock } from '../common/Skeleton'

function formatTime(timestamp) {
  if (!timestamp) return '—'
  try {
    const date = new Date(timestamp)
    if (isNaN(date.getTime())) return String(timestamp)
    return date.toLocaleString()
  } catch (e) {
    return String(timestamp)
  }
}

export function EvidenceTab() {
  const {
    chainStatus,
    setChainStatus,
    addToast,
    setActiveTab,
    setSelectedFindingId,
    setFindingsFilter
  } = useStore()

  const [evidence, setEvidence] = useState([])
  const [evidenceLoading, setEvidenceLoading] = useState(true)
  const [evidenceError, setEvidenceError] = useState(null)

  const [unregisteredMetadata, setUnregisteredMetadata] = useState({})
  const [sortCol, setSortCol] = useState('path')
  const [sortAsc, setSortAsc] = useState(true)
  const [verifyStatus, setVerifyStatus] = useState({})

  // Modal State
  const [activeModal, setActiveModal] = useState(null) // 'verify_hmac' | 'seal' | 'ignore' | 'retire' | null
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

  useEffect(() => {
    refreshData()
  }, [])

  async function handleRescan() {
    try {
      addToast('Rescanning evidence directory...', 'info')
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
    if (!modalPassword) {
      setModalError('Password required.')
      return
    }
    setModalLoading(true)
    setModalError('')
    setModalResult(null)
    try {
      const challenge = await getChainChallenge()
      const response = await computeSimpleChallengeResponse(modalPassword, challenge)
      const res = await postChainVerifyHmac({ challenge_id: challenge.challenge_id, response })
      setModalResult(res)

      // Refresh chain status
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
    if (!modalPassword) {
      setModalError('Password required.')
      return
    }
    setModalLoading(true)
    setModalError('')
    setModalResult(null)
    try {
      const challenge = await getChainChallenge()
      const response = await computeSimpleChallengeResponse(modalPassword, challenge)

      const fileSpecs = (chainStatus?.unregistered || []).map((path) => ({
        path,
        source: unregisteredMetadata[path]?.source || '',
        description: unregisteredMetadata[path]?.description || ''
      }))

      const res = await postChainSeal({
        challenge_id: challenge.challenge_id,
        response,
        file_specs: fileSpecs
      })

      if (res.sealed) {
        setModalResult(res)
        addToast(`Manifest version ${res.manifest_version} sealed successfully!`, 'success')
        setTimeout(() => {
          setActiveModal(null)
          setModalPassword('')
          setModalResult(null)
          refreshData()
        }, 1500)
      } else {
        throw new Error(res.error || 'Seal failed')
      }
    } catch (err) {
      setModalError(err.message || 'Seal failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleDeleteEvidence(e) {
    e.preventDefault()
    if (!modalReason) {
      setModalError('Reason is required.')
      return
    }
    if (!modalPassword) {
      setModalError('Password required.')
      return
    }
    setModalLoading(true)
    setModalError('')
    setModalResult(null)
    try {
      const challenge = await getChainChallenge()
      const response = await computeSimpleChallengeResponse(modalPassword, challenge)

      const res = await postChainDelete({
        challenge_id: challenge.challenge_id,
        response,
        path: pendingPath,
        reason: modalReason
      })

      if (res.deleted) {
        addToast(res.file_removed ? 'File permanently deleted from evidence.' : 'Stray record removed.', 'success')
        setModalResult({ success: true })
        setTimeout(() => {
          setActiveModal(null)
          setModalPassword('')
          setModalReason('')
          setModalResult(null)
          refreshData()
        }, 1500)
      } else {
        throw new Error(res.error || 'Delete failed')
      }
    } catch (err) {
      setModalError(err.message || 'Delete failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleIgnoreEvidence(e) {
    e.preventDefault()
    if (!modalReason) {
      setModalError('Reason is required.')
      return
    }
    if (!modalPassword) {
      setModalError('Password required.')
      return
    }
    setModalLoading(true)
    setModalError('')
    setModalResult(null)
    try {
      const challenge = await getChainChallenge()
      const response = await computeSimpleChallengeResponse(modalPassword, challenge)

      const res = await postChainIgnore({
        challenge_id: challenge.challenge_id,
        response,
        path: pendingPath,
        reason: modalReason
      })

      if (res.ignored) {
        addToast('File marked as ignored successfully!', 'success')
        setModalResult({ success: true })
        setTimeout(() => {
          setActiveModal(null)
          setModalPassword('')
          setModalReason('')
          setModalResult(null)
          refreshData()
        }, 1500)
      } else {
        throw new Error(res.error || 'Ignore failed')
      }
    } catch (err) {
      setModalError(err.message || 'Ignore failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleRetireEvidence(e) {
    e.preventDefault()
    if (!modalReason) {
      setModalError('Reason is required.')
      return
    }
    if (!modalPassword) {
      setModalError('Password required.')
      return
    }
    setModalLoading(true)
    setModalError('')
    setModalResult(null)
    try {
      const challenge = await getChainChallenge()
      const response = await computeSimpleChallengeResponse(modalPassword, challenge)

      const res = await postChainRetire({
        challenge_id: challenge.challenge_id,
        response,
        path: pendingPath,
        reason: modalReason
      })

      if (res.ignored || res.retired || res.manifest_version !== undefined) {
        addToast('File retired successfully!', 'success')
        setModalResult({ success: true })
        setTimeout(() => {
          setActiveModal(null)
          setModalPassword('')
          setModalReason('')
          setModalResult(null)
          refreshData()
        }, 1500)
      } else {
        throw new Error(res.error || 'Retire failed')
      }
    } catch (err) {
      setModalError(err.message || 'Retire failed')
    } finally {
      setModalLoading(false)
    }
  }

  async function handleTriggerAnchor() {
    try {
      addToast('Submitting Solana anchor transaction...', 'info')
      const result = await postChainAnchor()

      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)

      if (result.anchored) {
        addToast('Manifest anchored successfully!', 'success')
      } else {
        addToast('Anchor submitted but not yet confirmed. Check status in a few seconds.', 'warning')
      }
    } catch (err) {
      addToast(err.message || 'Solana anchor failed', 'error')
    }
  }

  async function handleProofExport() {
    try {
      addToast('Generating proof export from DB custody authority...', 'info')
      const result = await postChainProofExport()
      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)
      const pe = result.proof_export || {}
      if (pe.verified) {
        addToast('Proof export generated and verified against mounted evidence.', 'success')
      } else {
        addToast('Proof export recorded, but evidence verification reported issues.', 'warning')
      }
    } catch (err) {
      addToast(err.message || 'Proof export failed', 'error')
    }
  }

  async function handleVerifyEvidence(path) {
    setVerifyStatus((prev) => ({ ...prev, [path]: 'checking' }))
    try {
      const result = await postVerifyEvidence(path)
      if (result.status === 'verified') {
        setVerifyStatus((prev) => ({ ...prev, [path]: 'verified' }))
      } else if (result.status === 'failed') {
        setVerifyStatus((prev) => ({ ...prev, [path]: 'failed' }))
      } else {
        setVerifyStatus((prev) => ({ ...prev, [path]: result.status || 'unknown' }))
      }
    } catch (err) {
      setVerifyStatus((prev) => ({ ...prev, [path]: 'error' }))
    }
  }

  const sortedEvidence = useMemo(() => {
    return [...evidence].sort((a, b) => {
      const av = a[sortCol] || ''
      const bv = b[sortCol] || ''
      let cmp = 0
      if (typeof av === 'number' && typeof bv === 'number') {
        cmp = av - bv
      } else {
        cmp = String(av).localeCompare(String(bv))
      }
      return sortAsc ? cmp : -cmp
    })
  }, [evidence, sortCol, sortAsc])

  return (
    <div className="h-full overflow-y-auto p-5 space-y-4" style={{ background: 'var(--bg-base)' }}>
      {/* Header */}
      <div className="flex justify-between items-center pb-2 border-b" style={{ borderColor: 'var(--border-faint)' }}>
        <div className="flex items-center gap-2">
          <h1 className="font-display font-bold text-lg" style={{ color: 'var(--text-bright)' }}>Evidence Chain</h1>
          {/* Seal/custody authority badge (DB authority surfaces seal_status; file
              authority falls back to the manifest status). */}
          {chainStatus && (chainStatus.seal_status || chainStatus.status) && (
            <span
              data-testid="seal-status-badge"
              className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider"
              style={{
                background: 'var(--bg-raised)',
                color: (chainStatus.seal_status || chainStatus.status) === 'sealed' ? 'var(--jade)'
                  : (chainStatus.seal_status || chainStatus.status) === 'violated' ? 'var(--red)'
                  : 'var(--amber)',
                border: '1px solid var(--border-soft)',
              }}
              title={chainStatus.authority === 'db' ? 'Seal status from Postgres custody authority' : 'Seal status from file manifest'}
            >
              {chainStatus.seal_status || chainStatus.status}
              {chainStatus.manifest_version != null ? ` · v${chainStatus.manifest_version}` : ''}
              {chainStatus.authority === 'db' ? ' · db' : ''}
            </span>
          )}
        </div>
        <button onClick={handleRescan} className="px-3 py-1.5 rounded text-xs font-sans transition-colors cursor-pointer hover:bg-[rgba(255,255,255,0.05)] flex items-center gap-1"
          style={{ background: 'var(--bg-raised)', color: 'var(--text-primary)', border: '1px solid var(--border-soft)' }}>
          ↺ Rescan
        </button>
      </div>

      {/* HMAC Remind Bar */}
      {chainStatus && (
        <div className={`p-3 rounded border text-xs flex justify-between items-center transition-all ${
          chainStatus.hmac_verify_needed
            ? 'bg-[rgba(255,179,71,0.05)] border-[rgba(255,179,71,0.25)] text-[var(--amber)]'
            : 'bg-[rgba(0,255,148,0.05)] border-[rgba(0,255,148,0.20)] text-[var(--jade)]'
        }`}>
          <div className="flex items-center gap-2">
            <span>{chainStatus.hmac_verify_needed ? '⚠' : '✓'}</span>
            <span>
              {chainStatus.hmac_verify_needed
                ? chainStatus.hmac_last_verified_at
                  ? `Evidence chain HMAC verification is overdue (last: ${formatTime(chainStatus.hmac_last_verified_at)}).`
                  : 'Evidence chain HMAC has never been verified.'
                : `Evidence chain HMAC verified${
                    chainStatus.hmac_last_verified_at
                      ? ` — last verified ${formatTime(chainStatus.hmac_last_verified_at)}`
                      : ''
                  }${
                    chainStatus.hmac_last_verified_by
                      ? ` by ${chainStatus.hmac_last_verified_by}`
                      : ''
                  }.`}
            </span>
          </div>
          <button
            onClick={() => {
              setActiveModal('verify_hmac')
              setModalPassword('')
              setModalError('')
              setModalResult(null)
            }}
            className="px-2.5 py-1 rounded text-[11px] font-sans font-semibold transition-colors cursor-pointer"
            style={{
              background: chainStatus.hmac_verify_needed ? 'var(--amber-dim)' : 'var(--jade-dim)',
              color: chainStatus.hmac_verify_needed ? 'var(--amber)' : 'var(--jade)',
              border: `1px solid ${chainStatus.hmac_verify_needed ? 'var(--amber)' : 'var(--jade)'}`
            }}
          >
            {chainStatus.hmac_verify_needed ? 'Verify Now' : 'Re-verify'}
          </button>
        </div>
      )}

      {/* Two-Column Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Write Block Status */}
        <div className="p-4 rounded border flex flex-col justify-between" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
          <div>
            <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
              Write Block Status
            </p>
            {chainStatus ? (
              chainStatus.write_protected ? (
                <div className="bg-[rgba(0,255,148,0.04)] border border-[rgba(0,255,148,0.15)] text-[var(--jade)] p-3 rounded text-xs">
                  <div className="font-semibold flex items-center gap-1.5 mb-1">
                    <span>✓</span> Write Protection Active
                  </div>
                  <div className="text-[11px] opacity-80 font-mono">
                    Evidence directory is write-protected (mounted read-only{chainStatus.write_block_mount_point ? ` on ${chainStatus.write_block_mount_point}` : ''}).
                  </div>
                </div>
              ) : (
                <div className="bg-[rgba(255,179,71,0.06)] border border-[rgba(255,179,71,0.2)] text-[var(--amber)] p-3 rounded text-xs">
                  <div className="font-semibold flex items-center gap-1.5 mb-1">
                    <span>⚠</span> Write Protection Warning
                  </div>
                  <div className="text-[11px] opacity-80 mb-2">
                    Evidence directory is NOT write-protected (mounted read-write). Forensic best practice requires mounting evidence read-only.
                  </div>
                  <div className="mt-3">
                    <p className="text-[10px] uppercase font-sans font-semibold text-text-muted mb-1">Recommended Mount Command:</p>
                    <pre className="p-2 rounded bg-bg-void border border-border-faint text-text-bright font-mono text-[10px] select-all">
                      mount -o ro,noatime /dev/sdX /mnt/evidence
                    </pre>
                  </div>
                </div>
              )
            ) : (
              <div className="h-16 skeleton" />
            )}
          </div>
        </div>

        {/* Solana Anchoring */}
        <div className="p-4 rounded border flex flex-col justify-between" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
          <div>
            <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
              Solana Anchor Status
            </p>
            {chainStatus ? (
              (() => {
                const a = chainStatus.anchor || {}
                if (a.solana_tx && a.confirmed) {
                  return (
                    <div className="bg-[rgba(0,255,148,0.04)] border border-[rgba(0,255,148,0.15)] text-[var(--jade)] p-3 rounded text-xs flex justify-between items-start gap-2">
                      <div>
                        <div className="font-semibold flex items-center gap-1.5 mb-1">
                          <span className="inline-flex items-center gap-1.5 font-semibold">
                            <svg className="h-3.5 w-3.5 text-current" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
                            </svg>
                            On-chain Anchored
                          </span>
                        </div>
                        <div className="text-[11px] opacity-80 font-mono">
                          Manifest v{a.manifest_version} anchored on Solana ({a.cluster || 'mainnet'}) at {formatTime(a.timestamp)}
                        </div>
                      </div>
                      {a.explorer_url && (
                        <a href={a.explorer_url} target="_blank" rel="noopener noreferrer" className="text-[11px] font-semibold underline shrink-0 hover:text-[var(--text-bright)]">
                          Solscan ↗
                        </a>
                      )}
                    </div>
                  )
                } else if (a.solana_tx && !a.confirmed) {
                  return (
                    <div className="bg-[rgba(255,179,71,0.06)] border border-[rgba(255,179,71,0.2)] text-[var(--amber)] p-3 rounded text-xs flex justify-between items-start gap-2">
                      <div>
                        <div className="font-semibold flex items-center gap-1.5 mb-1">
                          <span className="inline-flex items-center gap-1.5 font-semibold">
                            <svg className="h-3.5 w-3.5 text-current animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            Anchor Pending
                          </span>
                        </div>
                        <div className="text-[11px] opacity-80 font-mono">
                          TX submitted, awaiting confirmation.
                        </div>
                      </div>
                      {a.explorer_url && (
                        <a href={a.explorer_url} target="_blank" rel="noopener noreferrer" className="text-[11px] font-semibold underline shrink-0 hover:text-[var(--text-bright)]">
                          Solscan ↗
                        </a>
                      )}
                    </div>
                  )
                } else if (a.anchoring_enabled && a.manifest_version > 0) {
                  return (
                    <div className="bg-[rgba(255,179,71,0.03)] border border-[rgba(255,179,71,0.15)] text-[var(--amber)] p-3 rounded text-xs flex justify-between items-center gap-4">
                      <div>
                        <div className="font-semibold flex items-center gap-1.5 mb-1">
                          <span className="inline-flex items-center gap-1.5 font-semibold">
                            <svg className="h-3.5 w-3.5 text-current" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
                            </svg>
                            Unanchored
                          </span>
                        </div>
                        <div className="text-[11px] opacity-80">
                          Manifest v{a.manifest_version} not yet anchored on Solana.
                        </div>
                      </div>
                      <button onClick={handleTriggerAnchor} className="px-2 py-1 rounded bg-[rgba(255,179,71,0.15)] border border-[var(--amber)] text-[var(--amber)] font-semibold text-[10px] shrink-0 hover:bg-[rgba(255,179,71,0.25)] transition-colors cursor-pointer">
                        Anchor Now
                      </button>
                    </div>
                  )
                } else {
                  return (
                    <div className="bg-transparent border border-[var(--border-soft)] text-[var(--text-muted)] p-3 rounded text-xs">
                      <span className="inline-flex items-start gap-1.5">
                        <svg className="h-3.5 w-3.5 text-amber shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <span>
                          Solana anchoring not configured. Set <code className="font-mono text-text-bright px-1 py-0.5 rounded bg-bg-raised border border-border-soft">SIFT_SOLANA_KEYPAIR</code> in the gateway environment to enable on-chain timestamping.{' '}
                          <a href="https://github.com/sift-mcps/sift-mcps/blob/main/docs/solana.md" target="_blank" rel="noopener noreferrer" className="text-cyan hover:underline ml-1">
                            Learn more ↗
                          </a>
                        </span>
                      </span>
                    </div>
                  )
                }
              })()
            ) : (
              <div className="h-16 skeleton" />
            )}
          </div>
        </div>

        {/* Proof Export (DB-derived custody proof bundle) */}
        {chainStatus && chainStatus.authority === 'db' && (
          <div className="p-4 rounded border flex flex-col justify-between" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
            <div>
              <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
                Custody Proof Export
              </p>
              {(() => {
                const pe = chainStatus.proof_export
                if (pe) {
                  return (
                    <div className="text-xs p-3 rounded border" style={{ borderColor: 'var(--border-soft)', color: 'var(--text-muted)' }}>
                      <div className="font-mono text-[11px]" style={{ color: pe.verified ? 'var(--jade)' : 'var(--amber)' }}>
                        {pe.verified ? 'Verified against mounted evidence' : 'Recorded — verification reported issues'}
                      </div>
                      <div className="text-[11px] opacity-80 mt-1 font-mono break-all">
                        v{pe.manifest_version} · {pe.export_kind} · {(pe.proof_hash || '').slice(0, 22)}…
                      </div>
                      {pe.verified_at && (
                        <div className="text-[11px] opacity-60 mt-1">Exported {formatTime(pe.verified_at)}</div>
                      )}
                    </div>
                  )
                }
                return (
                  <div className="text-xs p-3 rounded border" style={{ borderColor: 'var(--border-soft)', color: 'var(--text-muted)' }}>
                    No proof export recorded yet. Proof material is derived from Postgres custody authority and re-verified against mounted evidence.
                  </div>
                )
              })()}
            </div>
            <button
              onClick={handleProofExport}
              className="mt-3 px-2 py-1 rounded bg-[rgba(0,200,255,0.12)] border border-[var(--cyan)] text-[var(--cyan)] font-semibold text-[10px] self-start hover:bg-[rgba(0,200,255,0.22)] transition-colors cursor-pointer"
            >
              Generate Proof Export
            </button>
          </div>
        )}
      </div>

      {/* Custody Violations */}
      {chainStatus && (chainStatus.missing?.length > 0 || chainStatus.modified?.length > 0) && (
        <div className="p-4 rounded border" style={{ background: 'var(--crimson-dim)', borderColor: 'var(--crimson)', color: 'var(--crimson)' }}>
          <h4 className="font-bold text-xs flex items-center gap-1.5 mb-2">
            <span>🚨</span> Chain of Custody Violation
          </h4>

          {chainStatus.missing?.length > 0 && (
            <div className="text-xs mb-3">
              <strong className="block mb-1">Missing Files:</strong>
              <ul className="list-disc pl-5 space-y-1">
                {chainStatus.missing.map((f) => {
                  const path = typeof f === 'string' ? f : (f.path || '')
                  return (
                    <li key={path} className="font-mono">
                      <div className="flex justify-between items-center">
                        <span className="break-all">{path}</span>
                        <button
                          onClick={() => {
                            setPendingPath(path)
                            setActiveModal('retire')
                            setModalPassword('')
                            setModalReason('')
                            setModalError('')
                            setModalResult(null)
                          }}
                          className="px-2 py-0.5 rounded text-[10px] bg-[rgba(255,56,100,0.15)] border border-[var(--crimson)] text-[var(--crimson)] hover:bg-[rgba(255,56,100,0.25)] shrink-0 transition-colors cursor-pointer ml-4"
                        >
                          Retire File
                        </button>
                      </div>
                    </li>
                  )
                })}
              </ul>
            </div>
          )}

          {chainStatus.modified?.length > 0 && (
            <div className="text-xs">
              <strong className="block mb-1">Modified Files (Hash Mismatch):</strong>
              <ul className="list-disc pl-5 space-y-1">
                {chainStatus.modified.map((f) => {
                  const path = typeof f === 'string' ? f : (f.path || '')
                  return (
                    <li key={path} className="font-mono break-all">
                      {path}
                    </li>
                  )
                })}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Unregistered Files */}
      {chainStatus && chainStatus.unregistered?.length > 0 && (
        <div className="p-4 rounded border space-y-3" style={{ background: 'rgba(255,179,71,0.02)', borderColor: 'rgba(255,179,71,0.2)' }}>
          <div className="flex justify-between items-center flex-wrap gap-2">
            <h4 className="font-bold text-xs flex items-center gap-1.5" style={{ color: 'var(--text-bright)' }}>
              <span>📂</span> Unregistered Evidence Files Detected
            </h4>
            <button
              onClick={() => {
                setActiveModal('seal')
                setModalPassword('')
                setModalError('')
                setModalResult(null)
              }}
              className="px-3 py-1.5 rounded text-xs font-semibold bg-[var(--amber-dim)] border border-[var(--amber)] text-[var(--amber)] hover:bg-[rgba(255,179,71,0.25)] transition-colors cursor-pointer"
            >
              Seal Manifest ({chainStatus.unregistered.length} file{chainStatus.unregistered.length === 1 ? '' : 's'})
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--border-soft)', color: 'var(--text-muted)' }}>
                  <th className="py-2 pr-4 font-semibold w-1/3">Path</th>
                  <th className="py-2 pr-4 font-semibold w-1/3">Source Notes</th>
                  <th className="py-2 pr-4 font-semibold w-1/3">Description</th>
                  <th className="py-2 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ divideColor: 'var(--border-faint)' }}>
                {chainStatus.unregistered.map((path) => (
                  <tr key={path} style={{ color: 'var(--text-primary)' }}>
                    <td className="py-2 pr-4 font-mono break-all">{path}</td>
                    <td className="py-2 pr-4">
                      <input
                        type="text"
                        value={unregisteredMetadata[path]?.source || ''}
                        onChange={(e) => setUnregisteredMetadata(prev => ({
                          ...prev,
                          [path]: {
                            source: e.target.value,
                            description: prev[path]?.description || ''
                          }
                        }))}
                        placeholder="e.g. USB drive #1"
                        className="w-full px-2 py-1 rounded text-[11px] font-sans focus:outline-none"
                        style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                      />
                    </td>
                    <td className="py-2 pr-4">
                      <input
                        type="text"
                        value={unregisteredMetadata[path]?.description || ''}
                        onChange={(e) => setUnregisteredMetadata(prev => ({
                          ...prev,
                          [path]: {
                            source: prev[path]?.source || '',
                            description: e.target.value
                          }
                        }))}
                        placeholder="e.g. Acquired disk image"
                        className="w-full px-2 py-1 rounded text-[11px] font-sans focus:outline-none"
                        style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                      />
                    </td>
                    <td className="py-2 text-right whitespace-nowrap">
                      <button
                        onClick={() => {
                          setPendingPath(path)
                          setActiveModal('ignore')
                          setModalPassword('')
                          setModalReason('')
                          setModalError('')
                          setModalResult(null)
                        }}
                        className="px-2 py-1 rounded text-[10px] font-semibold border transition-colors hover:text-[var(--text-bright)] hover:border-[var(--text-ghost)] cursor-pointer"
                        style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-muted)' }}
                      >
                        Ignore
                      </button>
                      <button
                        onClick={() => {
                          setPendingPath(path)
                          setActiveModal('delete')
                          setModalPassword('')
                          setModalReason('')
                          setModalError('')
                          setModalResult(null)
                        }}
                        className="ml-2 px-2 py-1 rounded text-[10px] font-semibold border transition-colors hover:text-[var(--crimson)] hover:border-[var(--crimson)] cursor-pointer"
                        style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-muted)' }}
                        title="Permanently delete this file's bytes from the evidence directory"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Evidence Table */}
      <div className="space-y-3">
        <h3 className="font-semibold text-xs uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
          Registered Evidence ({evidence.length} file{evidence.length === 1 ? '' : 's'})
        </h3>

        {evidenceError && (
          <div className="text-xs p-2.5 rounded bg-[rgba(255,56,100,0.06)] border border-[rgba(255,56,100,0.2)] text-[var(--crimson)]">
            {evidenceError}
          </div>
        )}

        {evidenceLoading ? (
          <SkeletonBlock rows={5} gap={8} />
        ) : evidence.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-8 text-center border rounded-lg bg-bg-surface py-12" style={{ borderColor: 'var(--border-soft)' }}>
            <svg className="h-12 w-12 text-text-muted mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            <p className="text-sm font-semibold text-text-primary">No evidence files registered.</p>
            <p className="text-xs text-text-muted mt-1 max-w-xs mb-4">Use the Rescan button or add files to the evidence directory.</p>
            <button
              onClick={handleRescan}
              className="px-3 py-1.5 rounded text-xs font-sans font-semibold transition-colors cursor-pointer bg-cyan text-bg-base hover:bg-opacity-95"
              style={{ backgroundColor: 'var(--cyan)' }}
            >
              Rescan Directory
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto border rounded" style={{ borderColor: 'var(--border-soft)', background: 'var(--bg-surface)' }}>
            <table className="w-full text-left text-xs" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr className="border-b bg-[rgba(255,255,255,0.02)]" style={{ borderColor: 'var(--border-soft)', color: 'var(--text-muted)' }}>
                  <th className="py-2 px-3 font-semibold cursor-pointer hover:text-[var(--text-bright)] select-none" onClick={() => { setSortCol('path'); setSortAsc(!sortAsc) }}>
                    Path {sortCol === 'path' ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                  <th className="py-2 px-3 font-semibold cursor-pointer hover:text-[var(--text-bright)] select-none" onClick={() => { setSortCol('sha256'); setSortAsc(!sortAsc) }}>
                    SHA-256 {sortCol === 'sha256' ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                  <th className="py-2 px-3 font-semibold cursor-pointer hover:text-[var(--text-bright)] select-none" onClick={() => { setSortCol('description'); setSortAsc(!sortAsc) }}>
                    Description {sortCol === 'description' ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                  <th className="py-2 px-3 font-semibold cursor-pointer hover:text-[var(--text-bright)] select-none" onClick={() => { setSortCol('registered_at'); setSortAsc(!sortAsc) }}>
                    Registered At {sortCol === 'registered_at' ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                  <th className="py-2 px-3 font-semibold cursor-pointer hover:text-[var(--text-bright)] select-none" onClick={() => { setSortCol('registered_by'); setSortAsc(!sortAsc) }}>
                    Registered By {sortCol === 'registered_by' ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                  <th className="py-2 px-3 font-semibold">Referenced By</th>
                  <th className="py-2 px-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ divideColor: 'var(--border-faint)' }}>
                {sortedEvidence.map((ev) => {
                  const status = verifyStatus[ev.path]
                  return (
                    <tr key={ev.path} className="hover:bg-[rgba(255,255,255,0.01)] transition-colors" style={{ color: 'var(--text-primary)' }}>
                      <td className="py-2 px-3 font-mono break-all">{ev.path}</td>
                      <td className="py-2 px-3 font-mono" title={ev.sha256}>
                        {ev.sha256 ? `${ev.sha256.substring(0, 12)}...` : '—'}
                      </td>
                      <td className="py-2 px-3">{ev.description || '—'}</td>
                      <td className="py-2 px-3" style={{ whiteSpace: 'nowrap' }}>{formatTime(ev.registered_at)}</td>
                      <td className="py-2 px-3">{ev.registered_by || '—'}</td>
                      <td className="py-2 px-3">
                        <div className="flex flex-wrap gap-1">
                          {ev.referenced_by && ev.referenced_by.length > 0 ? (
                            ev.referenced_by.map((rid) => (
                              <button
                                key={rid}
                                onClick={() => {
                                  setSelectedFindingId(rid)
                                  setFindingsFilter('all')
                                  setActiveTab('findings')
                                }}
                                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[var(--cyan-dim)] text-[var(--cyan)] hover:bg-[rgba(0,212,255,0.25)] transition-colors cursor-pointer"
                              >
                                {rid}
                              </button>
                            ))
                          ) : (
                            <span className="text-[var(--text-ghost)]">—</span>
                          )}
                        </div>
                      </td>
                      <td className="py-2 px-3 text-right">
                        {status === 'checking' ? (
                          <span className="text-xs font-mono text-[var(--text-muted)] animate-pulse">Checking...</span>
                        ) : status === 'verified' ? (
                          <span className="text-xs font-mono text-[var(--jade)] font-semibold">Verified ✓</span>
                        ) : status === 'failed' ? (
                          <span className="text-xs font-mono text-[var(--crimson)] font-semibold">FAILED ⚠</span>
                        ) : status === 'error' ? (
                          <span className="text-xs font-mono text-[var(--crimson)]">Error</span>
                        ) : status ? (
                          <span className="text-xs font-mono text-[var(--text-muted)]">{status}</span>
                        ) : (
                          <button
                            onClick={() => handleVerifyEvidence(ev.path)}
                            className="px-2 py-1 rounded text-[10px] font-semibold border transition-colors hover:text-[var(--text-bright)] hover:border-[var(--text-ghost)] cursor-pointer"
                            style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-muted)' }}
                          >
                            Verify
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Verify HMAC Modal */}
      {activeModal === 'verify_hmac' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[rgba(7,9,14,0.8)] backdrop-blur-sm">
          <div className="w-full max-w-md p-5 rounded border space-y-4" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-soft)' }}>
            <h3 className="font-display font-bold text-base" style={{ color: 'var(--text-bright)' }}>Verify Evidence Chain HMAC</h3>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Enter password to derive key and verify all manifest entries against the cryptographic verification ledger.
            </p>

            <form onSubmit={handleVerifyHmac} className="space-y-4">
              {!modalResult && (
                <div className="space-y-1">
                  <label className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                    Examiner Password
                  </label>
                  <input
                    type="password"
                    value={modalPassword}
                    onChange={(e) => setModalPassword(e.target.value)}
                    placeholder="Enter password..."
                    disabled={modalLoading}
                    required
                    className="w-full px-3 py-2 rounded text-xs font-mono focus:outline-none"
                    style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                  />
                </div>
              )}

              {modalError && (
                <div className="text-xs p-2.5 rounded bg-[rgba(255,56,100,0.06)] border border-[rgba(255,56,100,0.2)] text-[var(--crimson)]">
                  {modalError}
                </div>
              )}

              {modalLoading && (
                <div className="text-xs font-mono text-[var(--text-muted)] animate-pulse">
                  Verifying...
                </div>
              )}

              {modalResult && (
                <div className="text-xs space-y-2">
                  {modalResult.ok ? (
                    <div className="p-3 rounded bg-[rgba(0,255,148,0.05)] border border-[rgba(0,255,148,0.2)] text-[var(--jade)]">
                      ✓ Verified {modalResult.verified} event(s). Chain is intact.
                    </div>
                  ) : (
                    <div className="p-3 rounded bg-[rgba(255,56,100,0.05)] border border-[rgba(255,56,100,0.2)] text-[var(--crimson)]">
                      ⚠ {modalResult.failed} event(s) FAILED.
                      {modalResult.failed_indices && (
                        <div className="font-mono text-[10px] mt-1 opacity-80">
                          Indices: {JSON.stringify(modalResult.failed_indices)}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setActiveModal(null)
                    setModalPassword('')
                    setModalResult(null)
                    setModalError('')
                  }}
                  className="px-3 py-1.5 rounded text-xs font-semibold border cursor-pointer"
                  style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-muted)' }}
                >
                  {modalResult ? 'Close' : 'Cancel'}
                </button>
                {!modalResult && (
                  <button
                    type="submit"
                    disabled={modalLoading}
                    className="px-4 py-1.5 rounded text-xs font-semibold cursor-pointer"
                    style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)', border: '1px solid var(--cyan)' }}
                  >
                    Verify
                  </button>
                )}
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Seal Manifest Modal */}
      {activeModal === 'seal' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[rgba(7,9,14,0.8)] backdrop-blur-sm">
          <div className="w-full max-w-md p-5 rounded border space-y-4" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-soft)' }}>
            <h3 className="font-display font-bold text-base" style={{ color: 'var(--text-bright)' }}>Seal Evidence Manifest</h3>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Enter password to sign and register all unregistered evidence files into the tamper-evident manifest.
            </p>
            <p className="text-[11px]" style={{ color: 'var(--amber)' }}>
              Large disk/memory images are hashed in full — this can take several minutes. Keep this window open until it completes.
            </p>

            <form onSubmit={handleSealEvidence} className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                  Examiner Password
                </label>
                <input
                  type="password"
                  value={modalPassword}
                  onChange={(e) => setModalPassword(e.target.value)}
                  placeholder="Enter password..."
                  disabled={modalLoading}
                  required
                  className="w-full px-3 py-2 rounded text-xs font-mono focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                />
              </div>

              {modalError && (
                <div className="text-xs p-2.5 rounded bg-[rgba(255,56,100,0.06)] border border-[rgba(255,56,100,0.2)] text-[var(--crimson)]">
                  {modalError}
                </div>
              )}

              {modalLoading && (
                <div className="text-xs font-mono text-[var(--text-muted)] animate-pulse">
                  Generating key and signing...
                </div>
              )}

              {modalResult && modalResult.sealed && (
                <div className="text-xs p-3 rounded bg-[rgba(0,255,148,0.05)] border border-[rgba(0,255,148,0.2)] text-[var(--jade)] space-y-1">
                  <div>✓ Manifest version {modalResult.manifest_version} sealed successfully!</div>
                  {modalResult.anchor && modalResult.anchor.solana_tx && (
                    <div className="text-[10px] font-mono opacity-80">
                      {modalResult.anchor.confirmed ? 'Confirmed: Anchored on Solana.' : 'Pending: Solana anchor pending.'}
                    </div>
                  )}
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setActiveModal(null)
                    setModalPassword('')
                    setModalResult(null)
                    setModalError('')
                  }}
                  className="px-3 py-1.5 rounded text-xs font-semibold border cursor-pointer"
                  style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalLoading}
                  className="px-4 py-1.5 rounded text-xs font-semibold cursor-pointer"
                  style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}
                >
                  Confirm
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Ignore Modal */}
      {activeModal === 'ignore' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[rgba(7,9,14,0.8)] backdrop-blur-sm">
          <div className="w-full max-w-md p-5 rounded border space-y-4" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-soft)' }}>
            <h3 className="font-display font-bold text-base" style={{ color: 'var(--text-bright)' }}>Ignore Unregistered File</h3>
            <div className="space-y-1">
              <span className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                Target File Path
              </span>
              <div className="text-xs font-mono break-all p-2 rounded" style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)' }}>
                {pendingPath}
              </div>
            </div>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Marking this file as ignored will exclude it from seal and verification checks. This action requires examiner justification and credentials.
            </p>

            <form onSubmit={handleIgnoreEvidence} className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                  Justification Reason
                </label>
                <input
                  type="text"
                  value={modalReason}
                  onChange={(e) => setModalReason(e.target.value)}
                  placeholder="e.g. Temporary scan/log file"
                  disabled={modalLoading}
                  required
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                  Examiner Password
                </label>
                <input
                  type="password"
                  value={modalPassword}
                  onChange={(e) => setModalPassword(e.target.value)}
                  placeholder="Enter password..."
                  disabled={modalLoading}
                  required
                  className="w-full px-3 py-2 rounded text-xs font-mono focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                />
              </div>

              {modalError && (
                <div className="text-xs p-2.5 rounded bg-[rgba(255,56,100,0.06)] border border-[rgba(255,56,100,0.2)] text-[var(--crimson)]">
                  {modalError}
                </div>
              )}

              {modalLoading && (
                <div className="text-xs font-mono text-[var(--text-muted)] animate-pulse">
                  Submitting ignore request...
                </div>
              )}

              {modalResult && (
                <div className="text-xs p-3 rounded bg-[rgba(0,255,148,0.05)] border border-[rgba(0,255,148,0.2)] text-[var(--jade)]">
                  ✓ File marked as ignored successfully!
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setActiveModal(null)
                    setModalPassword('')
                    setModalReason('')
                    setModalResult(null)
                    setModalError('')
                  }}
                  className="px-3 py-1.5 rounded text-xs font-semibold border cursor-pointer"
                  style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalLoading}
                  className="px-4 py-1.5 rounded text-xs font-semibold cursor-pointer border"
                  style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-bright)' }}
                >
                  Ignore File
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Modal */}
      {activeModal === 'delete' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[rgba(7,9,14,0.8)] backdrop-blur-sm">
          <div className="w-full max-w-md p-5 rounded border space-y-4" style={{ background: 'var(--bg-surface)', borderColor: 'var(--crimson)' }}>
            <h3 className="font-display font-bold text-base" style={{ color: 'var(--crimson)' }}>Delete Stray File</h3>
            <div className="space-y-1">
              <span className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                Target File Path
              </span>
              <div className="text-xs font-mono break-all p-2 rounded" style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)' }}>
                {pendingPath}
              </div>
            </div>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              This <strong style={{ color: 'var(--crimson)' }}>permanently removes the file's bytes</strong> from the evidence directory so it can no longer be read or indexed by the AI agent. Sealed evidence cannot be deleted. The removed file's SHA-256 and size are recorded in the append-only custody log. This action requires examiner justification and credentials.
            </p>

            <form onSubmit={handleDeleteEvidence} className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                  Justification Reason
                </label>
                <input
                  type="text"
                  value={modalReason}
                  onChange={(e) => setModalReason(e.target.value)}
                  placeholder="e.g. Stray/unauthorized file, not part of acquisition"
                  disabled={modalLoading}
                  required
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                  Examiner Password
                </label>
                <input
                  type="password"
                  value={modalPassword}
                  onChange={(e) => setModalPassword(e.target.value)}
                  placeholder="Enter password..."
                  disabled={modalLoading}
                  required
                  className="w-full px-3 py-2 rounded text-xs font-mono focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                />
              </div>

              {modalError && (
                <div className="text-xs p-2.5 rounded bg-[rgba(255,56,100,0.06)] border border-[rgba(255,56,100,0.2)] text-[var(--crimson)]">
                  {modalError}
                </div>
              )}

              {modalLoading && (
                <div className="text-xs font-mono text-[var(--text-muted)] animate-pulse">
                  Deleting file...
                </div>
              )}

              {modalResult && (
                <div className="text-xs p-3 rounded bg-[rgba(0,255,148,0.05)] border border-[rgba(0,255,148,0.2)] text-[var(--jade)]">
                  ✓ File deleted from evidence.
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setActiveModal(null)
                    setModalPassword('')
                    setModalReason('')
                    setModalResult(null)
                    setModalError('')
                  }}
                  className="px-3 py-1.5 rounded text-xs font-semibold border cursor-pointer"
                  style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalLoading}
                  className="px-4 py-1.5 rounded text-xs font-semibold cursor-pointer border"
                  style={{ background: 'transparent', borderColor: 'var(--crimson)', color: 'var(--crimson)' }}
                >
                  Delete File
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Retire Modal */}
      {activeModal === 'retire' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[rgba(7,9,14,0.8)] backdrop-blur-sm">
          <div className="w-full max-w-md p-5 rounded border space-y-4" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-soft)' }}>
            <h3 className="font-display font-bold text-base" style={{ color: 'var(--text-bright)' }}>Retire Missing File</h3>
            <div className="space-y-1">
              <span className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                Target File Path
              </span>
              <div className="text-xs font-mono break-all p-2 rounded" style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)' }}>
                {pendingPath}
              </div>
            </div>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Retiring a file will deactivate its entry in the manifest. The file will no longer be expected during checks. This requires reason and credentials.
            </p>

            <form onSubmit={handleRetireEvidence} className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                  Justification Reason
                </label>
                <input
                  type="text"
                  value={modalReason}
                  onChange={(e) => setModalReason(e.target.value)}
                  placeholder="e.g. Formally removed from scope"
                  disabled={modalLoading}
                  required
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-sans font-semibold uppercase tracking-wider block" style={{ color: 'var(--text-muted)' }}>
                  Examiner Password
                </label>
                <input
                  type="password"
                  value={modalPassword}
                  onChange={(e) => setModalPassword(e.target.value)}
                  placeholder="Enter password..."
                  disabled={modalLoading}
                  required
                  className="w-full px-3 py-2 rounded text-xs font-mono focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }}
                />
              </div>

              {modalError && (
                <div className="text-xs p-2.5 rounded bg-[rgba(255,56,100,0.06)] border border-[rgba(255,56,100,0.2)] text-[var(--crimson)]">
                  {modalError}
                </div>
              )}

              {modalLoading && (
                <div className="text-xs font-mono text-[var(--text-muted)] animate-pulse">
                  Submitting retire request...
                </div>
              )}

              {modalResult && (
                <div className="text-xs p-3 rounded bg-[rgba(0,255,148,0.05)] border border-[rgba(0,255,148,0.2)] text-[var(--jade)]">
                  ✓ File retired successfully!
                </div>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setActiveModal(null)
                    setModalPassword('')
                    setModalReason('')
                    setModalResult(null)
                    setModalError('')
                  }}
                  className="px-3 py-1.5 rounded text-xs font-semibold border cursor-pointer"
                  style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-muted)' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalLoading}
                  className="px-4 py-1.5 rounded text-xs font-semibold cursor-pointer border"
                  style={{ background: 'transparent', borderColor: 'var(--border-hard)', color: 'var(--text-bright)' }}
                >
                  Retire File
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
