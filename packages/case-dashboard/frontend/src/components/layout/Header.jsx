import { useState } from 'react'
import { useStore } from '../../store/useStore'
import { postLogout, postCaseActivate, getCaseActivateChallenge } from '../../api/endpoints'
import { computeSimpleChallengeResponse } from '../../api/crypto'

export function Header({ onLogout }) {
  const { user, activeCase, cases, delta, setActiveCase } = useStore()
  const [caseMenuOpen, setCaseMenuOpen] = useState(false)
  const [activatingCase, setActivatingCase] = useState(null)
  const [activatePassword, setActivatePassword] = useState('')
  const [activateErr, setActivateErr] = useState('')

  async function handleLogout() {
    await postLogout().catch(() => {})
    onLogout()
  }

  async function switchCase(c) {
    setCaseMenuOpen(false)
    if (c.active) return
    setActivatingCase(c)
  }

  async function confirmActivate(e) {
    e.preventDefault()
    setActivateErr('')
    try {
      const challenge = await getCaseActivateChallenge()
      const response = await computeSimpleChallengeResponse(activatePassword, challenge)
      setActivatePassword('')
      await postCaseActivate({ id: activatingCase.id, challenge_id: challenge.challenge_id, response })
      setActivatingCase(null)
    } catch (ex) {
      console.error('Activation failed:', ex)
      setActivateErr('Activation failed. Verify password and try again.')
    }
  }

  const agentPulse = delta.length > 0

  return (
    <>
      <header className="flex items-center h-[52px] px-4 shrink-0 border-b border-border-faint bg-bg-surface z-30"
        style={{ background: 'var(--bg-surface)' }}>
        {/* Branding */}
        <div className="flex items-center gap-2 mr-4">
          <span className="font-display font-extrabold text-sm tracking-tight" style={{ color: 'var(--text-bright)' }}>
            sift-mcps
          </span>
        </div>

        {/* Case selector */}
        <div className="relative">
          <button
            onClick={() => setCaseMenuOpen(!caseMenuOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono transition-colors"
            style={{ background: 'var(--bg-raised)', color: 'var(--text-primary)', border: '1px solid var(--border-soft)' }}
          >
            {activeCase ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: 'var(--jade)' }} />
                <span>{activeCase.id}</span>
              </>
            ) : (
              <span style={{ color: 'var(--text-muted)' }}>No case active</span>
            )}
            <span style={{ color: 'var(--text-muted)' }}>▾</span>
          </button>

          {caseMenuOpen && (
            <div className="absolute top-full left-0 mt-1 w-64 rounded shadow-lg z-40 overflow-hidden"
              style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-soft)' }}>
              {cases.map((c) => (
                <button key={c.id} onClick={() => switchCase(c)}
                  className="w-full text-left px-3 py-2 text-xs font-mono flex items-center gap-2 hover:bg-bg-raised transition-colors"
                  style={{ color: c.active ? 'var(--cyan)' : 'var(--text-primary)' }}>
                  <span className="w-1.5 h-1.5 rounded-full inline-block"
                    style={{ background: c.active ? 'var(--jade)' : 'var(--border-hard)' }} />
                  {c.id}
                </button>
              ))}
              {cases.length === 0 && (
                <p className="px-3 py-2 text-xs" style={{ color: 'var(--text-muted)' }}>No cases found</p>
              )}
            </div>
          )}
        </div>

        <div className="flex-1" />

        {/* Agent pulse */}
        <div className="flex items-center gap-1.5 mr-4 text-xs font-sans"
          style={{ color: agentPulse ? 'var(--jade)' : 'var(--text-muted)' }}>
          <span className={agentPulse ? 'pulse' : ''} style={{
            width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
            background: agentPulse ? 'var(--jade)' : 'var(--text-ghost)',
          }} />
          <span>{agentPulse ? 'activity' : 'idle'}</span>
        </div>

        {/* User */}
        <div className="flex items-center gap-2 text-xs font-sans" style={{ color: 'var(--text-muted)' }}>
          <span style={{ color: 'var(--text-primary)' }}>{user?.examiner ?? '—'}</span>
          {user?.role && (
            <span className="px-1.5 py-0.5 rounded font-mono text-[10px]"
              style={{ background: 'var(--bg-raised)', color: 'var(--text-muted)', border: '1px solid var(--border-faint)' }}>
              {user.role.toUpperCase()}
            </span>
          )}
          <button onClick={handleLogout}
            className="ml-1 px-2 py-1 rounded text-xs font-sans transition-colors hover:bg-bg-raised"
            style={{ color: 'var(--text-muted)', border: '1px solid var(--border-faint)' }}>
            Sign out
          </button>
        </div>
      </header>

      {/* Case activation modal */}
      {activatingCase && (
        <div className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(7,9,14,0.8)' }}
          onClick={() => setActivatingCase(null)}>
          <form onSubmit={confirmActivate} onClick={(e) => e.stopPropagation()}
            className="w-80 p-6 rounded-lg space-y-4"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-soft)' }}>
            <h2 className="text-sm font-sans font-semibold" style={{ color: 'var(--text-bright)' }}>
              Activate case: <span className="font-mono">{activatingCase.id}</span>
            </h2>
            {activateErr && <p className="text-xs" style={{ color: 'var(--crimson)' }}>{activateErr}</p>}
            <label className="block">
              <span className="text-xs font-sans uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Password</span>
              <input type="password" value={activatePassword}
                onChange={(e) => setActivatePassword(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded text-sm font-sans"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                autoFocus required />
            </label>
            <div className="flex gap-2">
              <button type="submit" className="flex-1 py-1.5 rounded text-xs font-sans font-semibold"
                style={{ background: 'var(--cyan)', color: 'var(--bg-base)' }}>
                Activate
              </button>
              <button type="button" onClick={() => setActivatingCase(null)}
                className="px-3 py-1.5 rounded text-xs font-sans"
                style={{ border: '1px solid var(--border-soft)', color: 'var(--text-muted)' }}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}
    </>
  )
}
