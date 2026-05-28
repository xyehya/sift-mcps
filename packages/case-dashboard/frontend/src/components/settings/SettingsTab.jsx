import { useState, useEffect } from 'react'
import { getTokens, postToken, deleteToken, postRotateToken } from '../../api/endpoints'
import { useStore } from '../../store/useStore'

export function SettingsTab() {
  const [tokens, setTokens] = useState([])
  const [loading, setLoading] = useState(false)
  const [agentId, setAgentId] = useState('')
  const [label, setLabel] = useState('')
  const [expiry, setExpiry] = useState('')
  const [newToken, setNewToken] = useState('')
  const [newTokenDisplay, setNewTokenDisplay] = useState(false)
  const { addToast } = useStore()

  useEffect(() => {
    fetchTokens()
  }, [])

  async function fetchTokens() {
    setLoading(true)
    try {
      const res = await getTokens()
      setTokens(res.tokens || [])
    } catch (ex) {
      addToast(ex.message || 'Failed to load tokens', 'error')
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

  return (
    <div className="h-full overflow-y-auto p-5 space-y-6" style={{ background: 'var(--bg-base)' }}>
      <h1 className="font-display font-bold text-lg text-text-bright">Settings</h1>

      {/* Copy-once banner */}
      {newTokenDisplay && (
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

      {/* Grid container */}
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
                  tokens.map((t) => (
                    <tr key={t.token_id} className="border-b" style={{ borderColor: 'var(--border-faint)' }}>
                      <td className="py-3 font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>{t.agent_id}</td>
                      <td className="py-3 animate-fade-in" style={{ color: 'var(--text-primary)' }}>{t.label}</td>
                      <td className="py-3 font-mono text-text-muted text-[11px]">
                        {t.expires_at ? new Date(t.expires_at).toLocaleString() : 'Never'}
                      </td>
                      <td className="py-3 text-right space-x-1.5">
                        <button onClick={() => handleRotate(t.token_id)} className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85"
                          style={{ background: 'var(--amber-dim)', color: 'var(--amber)', borderColor: 'var(--amber)' }}>
                          Rotate
                        </button>
                        <button onClick={() => handleRevoke(t.token_id)} className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85"
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
  )
}
