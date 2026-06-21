import { useCallback, useEffect, useState } from 'react'

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

// ─────────────────────────────────────────────────────────────────────────
// useEvidenceCustody — owns the evidence list + the chain-of-custody action
// handlers (rescan · verify-hmac · seal · ignore · delete · retire · reacquire
// · unseal · anchor · proof-export · per-item verify). Keeps EvidenceTab a thin
// orchestrator (≤400 lines). Mock/real split lives at the API adapter layer —
// no isMock branching here (AGENTS §3). Modal field state stays in the tab.
// ─────────────────────────────────────────────────────────────────────────

export function useEvidenceCustody({
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
}) {
  const [evidence, setEvidence] = useState([])
  const [evidenceLoading, setEvidenceLoading] = useState(true)
  const [evidenceError, setEvidenceError] = useState(null)
  const [verifyStatus, setVerifyStatus] = useState({})

  const refreshData = useCallback(async () => {
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
  }, [setChainStatus])

  useEffect(() => {
    // Initial data load on mount — intentional one-shot fetch into local state.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refreshData()
  }, [refreshData])

  // Shared re-auth guard: require password (+ reason for ledgered actions).
  function guard(needReason) {
    if (needReason && !modalReason) {
      setModalError('Reason is required.')
      return false
    }
    if (!modalPassword) {
      setModalError('Password required.')
      return false
    }
    setModalLoading(true)
    setModalError('')
    setModalResult(null)
    return true
  }

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

  async function handleTriggerAnchor() {
    try {
      addToast('Submitting Solana anchor transaction…', 'info')
      const result = await postChainAnchor()
      const freshStatus = await getChainStatus()
      if (freshStatus) setChainStatus(freshStatus)
      addToast(
        result.anchored
          ? 'Manifest anchored successfully!'
          : 'Anchor submitted but not yet confirmed. Check status in a few seconds.',
        result.anchored ? 'success' : 'warning',
      )
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
      addToast(
        pe.verified
          ? 'Proof export generated and verified against mounted evidence.'
          : 'Proof export recorded, but evidence verification reported issues.',
        pe.verified ? 'success' : 'warning',
      )
    } catch (err) {
      addToast(err.message || 'Proof export failed', 'error')
    }
  }

  async function handleVerifyEvidence(path) {
    setVerifyStatus((prev) => ({ ...prev, [path]: 'checking' }))
    try {
      const result = await postVerifyEvidence(path)
      setVerifyStatus((prev) => ({
        ...prev,
        [path]:
          result.status === 'verified'
            ? 'verified'
            : result.status === 'failed'
              ? 'failed'
              : result.status || 'unknown',
      }))
    } catch {
      setVerifyStatus((prev) => ({ ...prev, [path]: 'error' }))
    }
  }

  return {
    evidence,
    evidenceLoading,
    evidenceError,
    verifyStatus,
    refreshData,
    handleRescan,
    handleVerifyHmac,
    handleSealEvidence,
    handleIgnoreEvidence,
    handleDeleteEvidence,
    handleRetireEvidence,
    handleReacquireEvidence,
    handleUnsealEvidence,
    handleTriggerAnchor,
    handleProofExport,
    handleVerifyEvidence,
  }
}
