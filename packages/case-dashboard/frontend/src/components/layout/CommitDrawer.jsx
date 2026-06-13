import { useState, useRef } from 'react'
import { useStore } from '../../store/useStore'
import { postCommit, deleteDelta } from '../../api/endpoints'

export function CommitDrawer() {
  const { commitDrawerOpen, setCommitDrawerOpen, delta, setDelta, findings, addToast } = useStore()
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [success, setSuccess] = useState(false)
  const [holding, setHolding] = useState(false)
  const [holdProgress, setHoldProgress] = useState(0)
  const holdTimer = useRef(null)
  const holdInterval = useRef(null)

  function getFinding(id) {
    return findings.find((f) => f.id === id)
  }

  // id here is the finding's id (e.g. F-001) — used for DELETE and for local filter
  async function removeItem(findingId) {
    try {
      await deleteDelta(findingId)
      setDelta(delta.filter((d) => d.id !== findingId))
    } catch (ex) {
      addToast(ex.message, 'error')
    }
  }

  function startHold() {
    setHolding(true)
    setHoldProgress(0)
    const start = Date.now()
    holdInterval.current = setInterval(() => {
      const pct = Math.min(100, ((Date.now() - start) / 3000) * 100)
      setHoldProgress(pct)
    }, 50)
    holdTimer.current = setTimeout(async () => {
      clearInterval(holdInterval.current)
      setHolding(false)
      setHoldProgress(0)
      await doCommit()
    }, 3000)
  }

  function cancelHold() {
    clearTimeout(holdTimer.current)
    clearInterval(holdInterval.current)
    setHolding(false)
    setHoldProgress(0)
  }

  async function doCommit() {
    setErr('')
    try {
      // CL3a (B-MVP-017): the operator password is re-verified against Supabase
      // server-side (over TLS, same as login); no local HMAC challenge round-trip.
      const submittedPassword = password
      setPassword('')
      await postCommit({ password: submittedPassword })
      setDelta([])
      setSuccess(true)
      addToast('Changes committed successfully', 'success')
      setTimeout(() => { setSuccess(false); setCommitDrawerOpen(false) }, 2500)
    } catch (ex) {
      console.error('Commit failed:', ex)
      setErr('Commit failed — check your password and try again.')
    }
  }

  if (!commitDrawerOpen) return null

  const DELTA_COLOR = { approve: 'var(--jade)', reject: 'var(--crimson)', edit: 'var(--amber)' }

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40" style={{ background: 'rgba(7,9,14,0.6)' }}
        onClick={() => setCommitDrawerOpen(false)} />

      {/* Drawer */}
      <div className="fixed top-0 right-0 h-full w-[400px] z-50 flex flex-col"
        style={{ background: 'var(--bg-surface)', borderLeft: '1px solid var(--border-soft)' }}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: 'var(--border-faint)' }}>
          <h2 className="font-display font-bold text-sm" style={{ color: 'var(--text-bright)' }}>
            Commit staged changes
          </h2>
          <button onClick={() => setCommitDrawerOpen(false)} className="hover:text-text-primary" style={{ color: 'var(--text-muted)' }}>✕</button>
        </div>

        {success ? (
          <div className="flex-1 flex items-center justify-center flex-col gap-3">
            <span className="text-5xl">🔐</span>
            <p className="font-display font-bold text-lg" style={{ color: 'var(--jade)' }}>Committed</p>
            <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Evidence chain updated</p>
          </div>
        ) : (
          <>
            {/* Delta list */}
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {delta.length === 0 ? (
                <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>No staged changes.</p>
              ) : (
                delta.map((d) => {
                  const f = getFinding(d.id)
                  const color = DELTA_COLOR[d.action] ?? 'var(--text-muted)'
                  return (
                    <div key={d.id} className="flex items-center gap-2 p-2 rounded text-xs"
                      style={{
                        border: `1px dashed ${color}`,
                        background: color + '11',
                      }}>
                      <span className="font-mono w-4 text-center" style={{ color }}>{d.action === 'approve' ? '✓' : d.action === 'reject' ? '✗' : '✎'}</span>
                      <span className="font-mono shrink-0" style={{ color: 'var(--text-muted)', width: 44 }}>{d.id}</span>
                      <span className="flex-1 truncate font-sans" style={{ color: 'var(--text-primary)' }}>
                        {f?.title ?? d.id}
                      </span>
                      <button onClick={() => removeItem(d.id)} className="shrink-0 text-[10px] hover:text-crimson"
                        style={{ color: 'var(--text-muted)' }}>✕</button>
                    </div>
                  )
                })
              )}
            </div>

            {/* Password + hold-to-commit */}
            <div className="p-4 border-t space-y-3" style={{ borderColor: 'var(--border-faint)' }}>
              {err && <p className="text-xs" style={{ color: 'var(--crimson)' }}>{err}</p>}
              <label className="block">
                <span className="text-[10px] font-sans font-semibold uppercase tracking-wider"
                  style={{ color: 'var(--text-muted)' }}>Examiner password (HMAC signing)</span>
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                  className="mt-1 w-full px-3 py-2 rounded text-sm font-mono focus:outline-none transition-colors"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                  disabled={delta.length === 0} />
              </label>

              <div className="relative">
                <button
                  onMouseDown={startHold}
                  onMouseUp={cancelHold}
                  onMouseLeave={cancelHold}
                  onTouchStart={startHold}
                  onTouchEnd={cancelHold}
                  onTouchCancel={cancelHold}
                  onBlur={cancelHold}
                  disabled={delta.length === 0 || !password}
                  className="w-full py-2.5 rounded text-xs font-sans font-semibold select-none relative overflow-hidden disabled:opacity-40"
                  style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>
                  <span className="relative z-10">
                    {holding ? `Hold to confirm… ${Math.round(holdProgress)}%` : '↑ Hold to commit'}
                  </span>
                  {holding && (
                    <span className="absolute inset-0 z-0 transition-all"
                      style={{ width: `${holdProgress}%`, background: 'var(--jade)', opacity: 0.2 }} />
                  )}
                </button>
              </div>
              <p className="text-[10px] font-mono text-center" style={{ color: 'var(--text-muted)' }}>
                Hold for 3 seconds to confirm. This action is cryptographically signed.
              </p>
            </div>
          </>
        )}
      </div>
    </>
  )
}
