import { useState, useEffect } from 'react'
import {
  getTokens, postToken, deleteToken, postRotateToken, postReactivateToken,
  getPrincipals, postPrincipal, deletePrincipal,
} from '../../api/endpoints'
import { useStore } from '../../store/useStore'

export function SettingsTab() {
  const [tokens, setTokens] = useState([])
  const [legacyEnabled, setLegacyEnabled] = useState(false)
  const [loading, setLoading] = useState(false)
  const [agentId, setAgentId] = useState('')
  const [label, setLabel] = useState('')
  const [expiry, setExpiry] = useState('')
  const [newToken, setNewToken] = useState('')
  const [newTokenDisplay, setNewTokenDisplay] = useState(false)
  const { addToast } = useStore()

  // PR03A — target path: agent/service Supabase JWT principals.
  const [principals, setPrincipals] = useState([])
  const [pKind, setPKind] = useState('agent')
  const [pName, setPName] = useState('')
  const [pScopes, setPScopes] = useState('mcp:*')
  // Issued JWT session material — shown ONCE, never written to localStorage.
  const [issued, setIssued] = useState(null)

  useEffect(() => {
    fetchPrincipals()
    fetchTokens()
  }, [])

  async function fetchPrincipals() {
    try {
      const res = await getPrincipals()
      setPrincipals(res.principals || [])
    } catch (ex) {
      // 503 = Supabase auth not wired in this deployment; not an error to surface loudly.
    }
  }

  async function handleCreatePrincipal(e) {
    e.preventDefault()
    if (!pName) { addToast('Display name is required', 'warn'); return }
    try {
      const tool_scopes = pScopes.split(',').map((s) => s.trim()).filter(Boolean)
      const result = await postPrincipal({ kind: pKind, display_name: pName, tool_scopes })
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
    try {
      await deletePrincipal(type, id)
      addToast('Principal revoked', 'success')
      await fetchPrincipals()
    } catch (ex) {
      addToast(ex.message || 'Failed to revoke principal', 'error')
    }
  }

  async function fetchTokens() {
    setLoading(true)
    try {
      const res = await getTokens()
      setTokens(res.tokens || [])
      setLegacyEnabled(true)
    } catch (ex) {
      // PR02 legacy tokens are a compatibility surface; absence is fine.
      setLegacyEnabled(false)
    } finally {
      setLoading(false)
    }
  }

  async function handleCreateToken(e) {
    e.preventDefault()
    if (!agentId || !label) {
      addToast('Agent ID and Label are required', 'warn')
      return
    }

    try {
      const payload = {
        agent_id: agentId,
        label,
        role: 'agent',
      }
      if (expiry) {
        payload.expires_at = new Date(expiry).toISOString()
      }
      const result = await postToken(payload)
      setNewToken(result.token)
      setNewTokenDisplay(true)
      setAgentId('')
      setLabel('')
      setExpiry('')
      addToast('Token created successfully', 'success')
      await fetchTokens()
    } catch (ex) {
      addToast(ex.message || 'Failed to create token', 'error')
    }
  }

  async function handleRotate(tokenId) {
    if (!confirm('Are you sure you want to rotate this token? The old token will be revoked immediately and a new one will be displayed.')) {
      return
    }
    try {
      const result = await postRotateToken(tokenId)
      setNewToken(result.token)
      setNewTokenDisplay(true)
      addToast('Token rotated successfully', 'success')
      await fetchTokens()
    } catch (ex) {
      addToast(ex.message || 'Failed to rotate token', 'error')
    }
  }

  async function handleRevoke(tokenId) {
    if (!confirm('Are you sure you want to revoke this agent token? Any active agent using this token will be disconnected immediately.')) {
      return
    }
    try {
      await deleteToken(tokenId)
      addToast('Token revoked successfully', 'success')
      await fetchTokens()
    } catch (ex) {
      addToast(ex.message || 'Failed to revoke token', 'error')
    }
  }

  async function handleReactivate(tokenId) {
    if (!confirm('Are you sure you want to reactivate this agent token?')) {
      return
    }
    try {
      await postReactivateToken(tokenId)
      addToast('Token reactivated successfully', 'success')
      await fetchTokens()
    } catch (ex) {
      addToast(ex.message || 'Failed to reactivate token', 'error')
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
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">TYPE</th>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">NAME</th>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">STATUS</th>
                    <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px] text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {principals.length === 0 ? (
                    <tr><td colSpan="4" className="py-8 text-center text-text-muted font-mono">No agent/service principals.</td></tr>
                  ) : (
                    principals.map((p) => (
                      <tr key={`${p.principal_type}-${p.principal_id}`} className="border-b" style={{ borderColor: 'var(--border-faint)' }}>
                        <td className="py-3 font-mono text-text-muted">{p.principal_type}</td>
                        <td className="py-3 font-mono font-semibold text-text-primary">{p.display_name || p.principal_id}</td>
                        <td className="py-3 font-mono text-text-muted">{p.status || 'active'}</td>
                        <td className="py-3 text-right">
                          <button onClick={() => handleRevokePrincipal(p.principal_type, p.principal_id)}
                            className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85"
                            style={{ background: 'var(--crimson-dim)', color: 'var(--crimson)', borderColor: 'var(--crimson)' }}>
                            Revoke
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Legacy PR02 compatibility — only when token fallback is enabled */}
      {legacyEnabled && (
      <p className="text-[10px] font-sans font-semibold uppercase tracking-widest pt-2" style={{ color: 'var(--amber)' }}>
        LEGACY COMPATIBILITY — PR02 SERVICE TOKENS
      </p>
      )}

      {/* Copy-once banner */}
      {legacyEnabled && newTokenDisplay && (
        <div className="p-4 rounded border text-xs font-mono space-y-2 relative"
          style={{ background: 'var(--cyan-dim)', borderColor: 'var(--cyan)', color: 'var(--text-bright)' }}>
          <button onClick={() => setNewTokenDisplay(false)} className="absolute top-2 right-3 text-cyan font-bold text-lg hover:text-white">&times;</button>
          <div className="font-bold text-cyan text-sm mb-1">🔐 NEW AGENT TOKEN GENERATED</div>
          <p className="text-text-muted leading-relaxed font-sans text-xs">
            Copy this token now. It will not be shown again.
          </p>
          <div className="bg-bg-surface border border-border-soft p-2.5 rounded flex items-center justify-between gap-3 text-xs overflow-x-auto select-all">
            <span className="text-cyan font-mono font-semibold select-all break-all">{newToken}</span>
            <button onClick={() => {
              navigator.clipboard.writeText(newToken)
              addToast('Token copied to clipboard', 'success')
            }} className="px-3 py-1 rounded text-[10px] font-sans font-semibold border hover:opacity-85"
              style={{ background: 'var(--bg-raised)', borderColor: 'var(--border-soft)', color: 'var(--text-primary)' }}>
              Copy
            </button>
          </div>
        </div>
      )}

      {/* Grid container — legacy PR02 tokens only when fallback enabled */}
      {legacyEnabled && (
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Token Form */}
        <div className="lg:col-span-1 p-4 rounded border flex flex-col h-fit"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
          <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
            CREATE AGENT TOKEN
          </p>
          <form onSubmit={handleCreateToken} className="space-y-4">
            <div>
              <label className="block text-[10px] font-mono text-text-muted mb-1">AGENT ID *</label>
              <input type="text" placeholder="e.g. hermes-agent" value={agentId} onChange={(e) => setAgentId(e.target.value)} required
                className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
            </div>

            <div>
              <label className="block text-[10px] font-mono text-text-muted mb-1">LABEL *</label>
              <input type="text" placeholder="e.g. Production investigation key" value={label} onChange={(e) => setLabel(e.target.value)} required
                className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
            </div>

            <div>
              <label className="block text-[10px] font-mono text-text-muted mb-1">EXPIRY DATE (OPTIONAL)</label>
              <input type="datetime-local" value={expiry} onChange={(e) => setExpiry(e.target.value)}
                className="w-full px-3 py-2 rounded text-xs font-mono focus:outline-none"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
            </div>

            <button type="submit" className="w-full py-2 rounded text-xs font-sans font-semibold hover:opacity-85 border transition-opacity"
              style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)', borderColor: 'var(--cyan)' }}>
              Generate token
            </button>
          </form>
        </div>

        {/* Token Table */}
        <div className="lg:col-span-2 p-4 rounded border flex flex-col"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
          <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
            ACTIVE AGENT TOKENS
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--border-soft)' }}>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">AGENT ID</th>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">LABEL</th>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">EXPIRY</th>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px] text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="4" className="py-8 text-center text-text-muted font-mono animate-pulse">Loading active tokens…</td>
                  </tr>
                ) : tokens.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="py-8 text-center text-text-muted font-mono">No active agent tokens.</td>
                  </tr>
                ) : (
                  tokens.map((t) => {
                    const isDuplicate = tokens.filter(x => x.agent_id === t.agent_id && x.label === t.label).length > 1;
                    return (
                      <tr key={t.token_id} className="border-b" style={{ borderColor: 'var(--border-faint)' }}>
                        <td className="py-3 font-mono font-semibold" style={{ color: t.revoked_at ? 'var(--text-muted)' : 'var(--text-primary)' }}>{t.agent_id}</td>
                        <td className="py-3 animate-fade-in" style={{ color: t.revoked_at ? 'var(--text-muted)' : 'var(--text-primary)' }}>
                          {t.label}
                          {t.revoked_at && (
                            <span className="px-1.5 py-0.5 ml-2 rounded font-mono text-[9px] bg-bg-raised text-text-muted border border-border-faint">
                              INACTIVE
                            </span>
                          )}
                          {isDuplicate && (
                            <span className="text-[10px] text-text-muted ml-1.5 font-mono">
                              ({t.created_at ? new Date(t.created_at).toLocaleString() : t.token_id.slice(0, 8)})
                            </span>
                          )}
                        </td>
                        <td className="py-3 font-mono text-text-muted text-[11px]">
                          {t.expires_at ? new Date(t.expires_at).toLocaleString() : 'Never'}
                        </td>
                      <td className="py-3 text-right space-x-1.5">
                        <button onClick={() => handleRotate(t.token_id)} className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85"
                          style={{ background: 'var(--amber-dim)', color: 'var(--amber)', borderColor: 'var(--amber)' }}>
                          Rotate
                        </button>
                        {t.revoked_at ? (
                          <button onClick={() => handleReactivate(t.token_id)} className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85"
                            style={{ background: 'var(--jade-dim)', color: 'var(--jade)', borderColor: 'var(--jade)' }}>
                            Reactivate
                          </button>
                        ) : (
                          <button onClick={() => handleRevoke(t.token_id)} className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85"
                            style={{ background: 'var(--crimson-dim)', color: 'var(--crimson)', borderColor: 'var(--crimson)' }}>
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
      )}
    </div>
  )
}
