import { useCallback, useEffect, useState } from 'react'

import { getPrincipals, postPrincipal, deletePrincipal } from '@/api/endpoints'

// ─────────────────────────────────────────────────────────────────────────
// usePrincipals — owns the agent/service JWT principal list, the issue-form
// fields, the issued-once token material (held in memory ONLY, never persisted),
// the live `nowMs` clock for TTL, and the create/revoke flows. Keeps SettingsTab
// a thin orchestrator. Issuing/revoking a credential is a sensitive action: the
// gateway re-verifies the operator password against Supabase (B-MVP-022/CL3b).
// Mock/real split is at the API adapter layer — no isMock here (§3).
// ─────────────────────────────────────────────────────────────────────────

const EMPTY_FORM = { kind: 'agent', name: '', scopes: 'mcp:*', password: '' }

export function usePrincipals({ addToast }) {
  const [principals, setPrincipals] = useState([])
  const [loading, setLoading] = useState(false)
  const [revoking, setRevoking] = useState(null)
  const [form, setForm] = useState(EMPTY_FORM)
  // Issued JWT session material — shown ONCE, never written to localStorage.
  const [issued, setIssued] = useState(null)
  const [nowMs, setNowMs] = useState(() => Date.now())

  const setField = useCallback((field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }))
  }, [])

  const fetchPrincipals = useCallback(async () => {
    setLoading(true)
    try {
      const res = await getPrincipals()
      setPrincipals(res.principals || [])
    } catch (ex) {
      addToast(ex.message || 'Failed to load principals', 'error')
    } finally {
      setLoading(false)
    }
  }, [addToast])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchPrincipals()
  }, [fetchPrincipals])

  // Tick the TTL clock every minute (live TTL_REMAINING column).
  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 60000)
    return () => clearInterval(id)
  }, [])

  async function handleCreate(e) {
    if (e) e.preventDefault()
    if (!form.name) {
      addToast('Display name is required', 'warn')
      return
    }
    if (!form.password) {
      addToast('Confirm your operator password to issue a credential', 'warn')
      return
    }
    try {
      const tool_scopes = form.scopes
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      // Issuing an agent/service credential is sensitive: the gateway re-verifies
      // the operator password against Supabase (B-MVP-022/CL3b).
      const result = await postPrincipal({
        kind: form.kind,
        display_name: form.name,
        tool_scopes,
        password: form.password,
      })
      // Token material returned exactly once. Hold in memory only for display.
      setIssued(result)
      setForm((prev) => ({ ...prev, name: '', password: '' }))
      addToast('Principal created', 'success')
      await fetchPrincipals()
    } catch (ex) {
      addToast(ex.message || 'Failed to create principal', 'error')
    }
  }

  async function handleRevoke(type, id) {
    if (!window.confirm('Revoke this principal? Its JWT session is disabled immediately and cannot be restored.')) {
      return
    }
    const key = `${type}-${id}`
    setRevoking(key)
    try {
      await deletePrincipal(type, id)
      setPrincipals((current) =>
        current.map((p) =>
          p.principal_type === type && p.principal_id === id ? { ...p, status: 'revoked' } : p,
        ),
      )
      addToast('Principal revoked', 'success')
      await fetchPrincipals()
    } catch (ex) {
      addToast(ex.message || 'Failed to revoke principal', 'error')
    } finally {
      setRevoking(null)
    }
  }

  return {
    principals,
    loading,
    revoking,
    form,
    setField,
    issued,
    clearIssued: () => setIssued(null),
    nowMs,
    handleCreate,
    handleRevoke,
  }
}
