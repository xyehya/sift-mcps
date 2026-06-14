import { useState, useEffect } from 'react'
import {
  getPrincipals, postPrincipal, deletePrincipal,
} from '../../api/endpoints'
import { useStore } from '../../store/useStore'

function dateMs(value) {
  if (!value) return null
  const parsed = typeof value === 'number' ? value * 1000 : Date.parse(value)
  return Number.isFinite(parsed) ? parsed : null
}

function formatDateTime(value) {
  const ms = dateMs(value)
  return ms === null ? 'Not recorded' : new Date(ms).toLocaleString()
}

function formatTtl(expiresAt, nowMs) {
  const expiresMs = dateMs(expiresAt)
  if (expiresMs === null) return 'Not recorded'
  const remaining = Math.max(0, expiresMs - nowMs)
  if (remaining <= 0) return 'Expired'
  const totalMinutes = Math.floor(remaining / 60000)
  const days = Math.floor(totalMinutes / 1440)
  const hours = Math.floor((totalMinutes % 1440) / 60)
  const minutes = totalMinutes % 60
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

function principalStatus(principal, nowMs) {
  const raw = String(principal.status || 'active').toLowerCase()
  if (['revoked', 'disabled', 'archived'].includes(raw)) return raw
  const expiresMs = dateMs(principal.last_issued_expires_at)
  if (expiresMs !== null && expiresMs <= nowMs) return 'expired'
  return raw
}

function statusStyle(status) {
  if (status === 'active') {
    return { background: 'var(--jade-dim)', color: 'var(--jade)', borderColor: 'var(--jade)' }
  }
  if (status === 'expired') {
    return { background: 'var(--amber-dim)', color: 'var(--amber)', borderColor: 'var(--amber)' }
  }
  return { background: 'var(--bg-raised)', color: 'var(--text-muted)', borderColor: 'var(--border-soft)' }
}

function tokenTypeLabel(principal) {
  return principal.token_type === 'supabase_jwt' ? 'Supabase JWT' : (principal.token_type || 'JWT session')
}

export function SettingsTab() {
  const addToast = useStore((state) => state.addToast)

  // PR03A — target path: agent/service Supabase JWT principals.
  const [principals, setPrincipals] = useState([])
  const [loadingPrincipals, setLoadingPrincipals] = useState(false)
  const [revokingPrincipal, setRevokingPrincipal] = useState(null)
  const [pKind, setPKind] = useState('agent')
  const [pName, setPName] = useState('')
  const [pScopes, setPScopes] = useState('mcp:*')
  const [pPassword, setPPassword] = useState('')
  // Issued JWT session material — shown ONCE, never written to localStorage.
  const [issued, setIssued] = useState(null)
  const [nowMs, setNowMs] = useState(() => Date.now())

  useEffect(() => {
    fetchPrincipals()
  }, [])

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 60000)
    return () => clearInterval(id)
  }, [])

  async function fetchPrincipals() {
    setLoadingPrincipals(true)
    try {
      const res = await getPrincipals()
      setPrincipals(res.principals || [])
    } catch (ex) {
      addToast(ex.message || 'Failed to load principals', 'error')
    } finally {
      setLoadingPrincipals(false)
    }
  }

  async function handleCreatePrincipal(e) {
    e.preventDefault()
    if (!pName) { addToast('Display name is required', 'warn'); return }
    if (!pPassword) { addToast('Confirm your operator password to issue a credential', 'warn'); return }
    try {
      const tool_scopes = pScopes.split(',').map((s) => s.trim()).filter(Boolean)
      // Issuing an agent/service credential is a sensitive action: the gateway
      // re-verifies the operator password against Supabase (B-MVP-022/CL3b).
      const result = await postPrincipal({ kind: pKind, display_name: pName, tool_scopes, password: pPassword })
      setPPassword('')
      // Token material returned exactly once. Hold in memory only for display.
      setIssued(result)
      setPName('')
      addToast('Principal created', 'success')
      await fetchPrincipals()
    } catch (ex) {
      addToast(ex.message || 'Failed to create principal', 'error')
    }
  }

  async function handleRevokePrincipal(type, id) {
    if (!confirm('Revoke this principal? Its JWT session is disabled immediately and cannot be restored.')) {
      return
    }
    const key = `${type}-${id}`
    setRevokingPrincipal(key)
    try {
      await deletePrincipal(type, id)
      setPrincipals((current) => current.map((p) => (
        p.principal_type === type && p.principal_id === id ? { ...p, status: 'revoked' } : p
      )))
      addToast('Principal revoked', 'success')
      await fetchPrincipals()
    } catch (ex) {
      addToast(ex.message || 'Failed to revoke principal', 'error')
    } finally {
      setRevokingPrincipal(null)
    }
  }

  return (
    <div className="h-full overflow-y-auto p-5 space-y-6" style={{ background: 'var(--bg-base)' }}>
      <h1 className="font-display font-bold text-lg text-text-bright">Settings</h1>

      {/* PR03A target — agent/service JWT principals */}
      <div>
        <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
          AGENT / SERVICE JWT SESSIONS
        </p>

        {/* Issued-once banner — token material shown a single time, not recoverable */}
        {issued && (
          <div className="p-4 rounded border text-xs font-mono space-y-2 relative mb-4"
            style={{ background: 'var(--cyan-dim)', borderColor: 'var(--cyan)', color: 'var(--text-bright)' }}>
            <button onClick={() => setIssued(null)} className="absolute top-2 right-3 text-cyan font-bold text-lg hover:text-white">&times;</button>
            <div className="font-bold text-cyan text-sm mb-1">NEW JWT SESSION ISSUED</div>
            <p className="text-text-muted leading-relaxed font-sans text-xs">
              Copy these tokens now. They are shown once and cannot be recovered.
            </p>
            <div className="bg-bg-surface border border-border-soft p-2.5 rounded space-y-1 text-[11px] break-all">
              <div><span className="text-text-muted">principal:</span> <span className="text-cyan">{issued.principal_type}/{issued.principal_id}</span></div>
              <div><span className="text-text-muted">token_type:</span> <span className="text-text-primary">Supabase JWT</span></div>
              <div><span className="text-text-muted">expires_at:</span> <span className="text-text-primary">{formatDateTime(issued.expires_at)}</span></div>
              <div><span className="text-text-muted">ttl_remaining:</span> <span className="text-text-primary">{formatTtl(issued.expires_at, nowMs)}</span></div>
              <div><span className="text-text-muted">access_token:</span> <span className="text-cyan select-all">{issued.access_token}</span></div>
              <div><span className="text-text-muted">refresh_token:</span> <span className="text-cyan select-all">{issued.refresh_token}</span></div>
              <div><span className="text-text-muted">fingerprint:</span> <span className="text-text-primary">{issued.token_fingerprint}</span></div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 p-4 rounded border flex flex-col h-fit"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
            <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
              ISSUE JWT SESSION
            </p>
            <form onSubmit={handleCreatePrincipal} className="space-y-4">
              <div>
                <label className="block text-[10px] font-mono text-text-muted mb-1">KIND</label>
                <select value={pKind} onChange={(e) => setPKind(e.target.value)}
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}>
                  <option value="agent">agent</option>
                  <option value="service">service</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-mono text-text-muted mb-1">DISPLAY NAME *</label>
                <input type="text" placeholder="e.g. Hermes investigation agent" value={pName} onChange={(e) => setPName(e.target.value)} required
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-text-muted mb-1">TOOL SCOPES (comma-separated)</label>
                <input type="text" placeholder="mcp:* or tool:foo, namespace:bar" value={pScopes} onChange={(e) => setPScopes(e.target.value)}
                  className="w-full px-3 py-2 rounded text-xs font-mono focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-text-muted mb-1">OPERATOR PASSWORD *</label>
                <input type="password" placeholder="Re-auth: confirm your password" value={pPassword} onChange={(e) => setPPassword(e.target.value)} required autoComplete="current-password"
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
                <p className="text-[10px] mt-1" style={{ color: 'var(--text-ghost)' }}>Issuing a credential is a sensitive action — re-verified against Supabase.</p>
              </div>
              <button type="submit" className="w-full py-2 rounded text-xs font-sans font-semibold hover:opacity-85 border transition-opacity"
                style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)', borderColor: 'var(--cyan)' }}>
                Issue session
              </button>
            </form>
          </div>

          <div className="lg:col-span-2 p-4 rounded border flex flex-col"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
            <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
              ACTIVE PRINCIPALS
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b" style={{ borderColor: 'var(--border-soft)' }}>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">TOKEN TYPE</th>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">NAME</th>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">STATUS</th>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">TTL REMAINING</th>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">SCOPES</th>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px] text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {loadingPrincipals ? (
                    <tr><td colSpan="6" className="py-8 text-center text-text-muted font-mono animate-pulse">Loading principals...</td></tr>
                  ) : principals.length === 0 ? (
                    <tr><td colSpan="6" className="py-8 text-center text-text-muted font-mono">No agent/service principals.</td></tr>
                  ) : (
                    principals.map((p) => {
                      const status = principalStatus(p, nowMs)
                      const revokeKey = `${p.principal_type}-${p.principal_id}`
                      const revoked = ['revoked', 'disabled', 'archived'].includes(String(p.status || '').toLowerCase())
                      const revokeDisabled = revoked || revokingPrincipal === revokeKey
                      return (
                        <tr key={revokeKey} className="border-b" style={{ borderColor: 'var(--border-faint)' }}>
                          <td className="py-3 align-top">
                            <div className="font-mono text-text-primary">{tokenTypeLabel(p)}</div>
                            <div className="font-mono text-[10px] text-text-muted">{p.principal_type}</div>
                          </td>
                          <td className="py-3 align-top">
                            <div className="font-mono font-semibold text-text-primary">{p.display_name || p.principal_id}</div>
                            <div className="font-mono text-[10px] text-text-muted">{p.principal_id}</div>
                          </td>
                          <td className="py-3 align-top">
                            <span className="px-1.5 py-0.5 rounded border font-mono text-[9px] font-semibold uppercase"
                              style={statusStyle(status)}>
                              {status}
                            </span>
                          </td>
                          <td className="py-3 align-top font-mono text-[11px] text-text-muted">
                            <div>{formatTtl(p.last_issued_expires_at, nowMs)}</div>
                            <div className="text-[10px] text-text-ghost">{formatDateTime(p.last_issued_expires_at)}</div>
                          </td>
                          <td className="py-3 align-top font-mono text-[10px] text-text-muted max-w-[220px]">
                            {(p.tool_scopes || []).length > 0 ? (p.tool_scopes || []).join(', ') : 'none'}
                          </td>
                          <td className="py-3 text-right align-top">
                            <button onClick={() => handleRevokePrincipal(p.principal_type, p.principal_id)}
                              disabled={revokeDisabled}
                              className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85 disabled:opacity-40 disabled:cursor-not-allowed"
                              style={revokeDisabled
                                ? { background: 'var(--bg-raised)', color: 'var(--text-muted)', borderColor: 'var(--border-soft)' }
                                : { background: 'var(--crimson-dim)', color: 'var(--crimson)', borderColor: 'var(--crimson)' }}>
                              {revoked ? 'Revoked' : revokingPrincipal === revokeKey ? 'Revoking...' : 'Revoke'}
                            </button>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

    </div>
  )
}
