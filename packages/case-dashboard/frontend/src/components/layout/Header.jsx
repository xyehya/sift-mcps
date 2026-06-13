import { useState, useRef, useEffect } from 'react'
import { useStore } from '../../store/useStore'
import { postLogout, postCaseActivate, getCaseActivateChallenge, postCaseCreate } from '../../api/endpoints'
import { Icon } from '../common/Icon'

export function Header({ onLogout }) {
  const {
    user, activeCase, cases, delta, setActiveCase,
    setFindings, setTimeline, setDelta, setChainStatus,
    setIocs, setTodos, setReports, setSummary, setIsLoading,
    chainStatus,
  } = useStore()
  const [caseMenuOpen, setCaseMenuOpen] = useState(false)
  const [activatingCase, setActivatingCase] = useState(null)
  const [activatePassword, setActivatePassword] = useState('')
  const [activateErr, setActivateErr] = useState('')
  const [activating, setActivating] = useState(false)
  // Create-case modal state
  const [creatingCase, setCreatingCase] = useState(false)
  const [newCaseName, setNewCaseName] = useState('')
  const [newCaseTitle, setNewCaseTitle] = useState('')
  const [newCaseSynopsis, setNewCaseSynopsis] = useState('')
  const [createErr, setCreateErr] = useState('')
  const [creating, setCreating] = useState(false)
  const menuRef = useRef(null)

  const isExaminer = (user?.role || '').toLowerCase() === 'examiner'

  useEffect(() => {
    function handleClickOutside(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setCaseMenuOpen(false)
      }
    }
    if (caseMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [caseMenuOpen])

  function handleLogout() {
    postLogout().catch(() => {})
    onLogout()
  }

  function switchCase(c) {
    setCaseMenuOpen(false)
    if (c.active) return
    setActivatingCase(c)
  }

  async function confirmActivate(e) {
    e.preventDefault()
    setActivateErr('')
    setActivating(true)
    try {
      const challenge = await getCaseActivateChallenge()
      // DB/Supabase authority mode returns {required:false, authority:'postgres'}
      // — case activation is gated by the Supabase session itself, so there is no
      // per-action re-auth. The file-backed branch (CL3a, B-MVP-017) re-verifies
      // the operator password against Supabase server-side.
      const dbAuthority = challenge?.required === false
      const payload = { case_id: activatingCase.id }
      if (!dbAuthority) {
        payload.password = activatePassword
      }
      setActivatePassword('')
      await postCaseActivate(payload)
      setActivatingCase(null)
      setActivating(false)
      // Reset all case-scoped data; next poll will pick up the new case
      setFindings([])
      setTimeline([])
      setDelta([])
      setChainStatus(null)
      setIocs([])
      setTodos([])
      setReports([])
      setSummary(null)
      setActiveCase(null)
      setIsLoading(true)
    } catch (ex) {
      console.error('Activation failed:', ex)
      setActivating(false)
      setActivateErr('Activation failed. Verify password and try again.')
    }
  }

  function openCreate() {
    setCaseMenuOpen(false)
    setCreateErr('')
    setNewCaseName('')
    setNewCaseTitle('')
    setNewCaseSynopsis('')
    setCreatingCase(true)
  }

  async function confirmCreate(e) {
    e.preventDefault()
    setCreateErr('')
    const casename = newCaseName.trim().toLowerCase()
    const title = newCaseTitle.trim()
    if (!casename || !title) {
      setCreateErr('Case name and title are required.')
      return
    }
    setCreating(true)
    try {
      // Backend computes case_id + directory and auto-activates the new case.
      const synopsis = newCaseSynopsis.trim()
      await postCaseCreate(synopsis ? { casename, title, description: synopsis } : { casename, title })
      setCreatingCase(false)
      setCreating(false)
      // Reset case-scoped data; next poll picks up the newly active case.
      setFindings([])
      setTimeline([])
      setDelta([])
      setChainStatus(null)
      setIocs([])
      setTodos([])
      setReports([])
      setSummary(null)
      setActiveCase(null)
      setIsLoading(true)
    } catch (ex) {
      console.error('Case creation failed:', ex)
      setCreating(false)
      let msg = 'Case creation failed. Check your role and try again.'
      if (ex?.message) {
        try { msg = JSON.parse(ex.message).error || msg } catch { msg = ex.message }
      }
      setCreateErr(msg)
    }
  }

  const agentPulse = delta.length > 0
  const activeCaseId = activeCase?.case_id || activeCase?.id

  const isError = chainStatus?.status === 'violation'
  const isProcessing = agentPulse
  const isIdle = !isProcessing && !isError

  let agentStatusLabel = 'idle'
  let agentStatusColor = '#94a3b8'
  let agentStatusTooltip = 'Agent status: idle — No AI analysis tasks running.'

  if (isError) {
    agentStatusLabel = 'error'
    agentStatusColor = '#ef4444'
    agentStatusTooltip = 'Agent status: error — Integrity violation or system error.'
  } else if (isProcessing) {
    agentStatusLabel = 'processing'
    agentStatusColor = '#eab308'
    agentStatusTooltip = 'Agent status: processing — AI analysis tasks are active.'
  }

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
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setCaseMenuOpen(!caseMenuOpen)}
            className="flex items-center gap-2 px-3 py-1.5 rounded border transition-colors cursor-pointer text-text-primary hover:bg-bg-raised hover:border-text-muted bg-bg-surface font-mono text-xs"
            style={{ borderColor: 'var(--border-soft)' }}
          >
            {activeCase ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full inline-block shrink-0" style={{ background: 'var(--jade)' }} />
                <span className="font-semibold">{activeCaseId}</span>
              </>
            ) : (
              <span className="text-text-muted">No case active</span>
            )}
            <Icon name="chevron-down" className="w-4 h-4 text-text-primary shrink-0 transition-transform" style={{ transform: caseMenuOpen ? 'rotate(180deg)' : 'none' }} />
          </button>

          {caseMenuOpen && (
            <div className="absolute top-full left-0 mt-1 w-72 rounded shadow-lg z-40 overflow-hidden"
              style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border-soft)' }}>
              {cases.map((c) => (
                <button key={c.id} onClick={() => switchCase(c)}
                  className="w-full text-left px-3 py-2 text-xs font-mono flex items-center gap-2 hover:bg-bg-raised transition-colors border-b border-border-faint last:border-b-0"
                  style={{ color: c.active ? 'var(--cyan)' : 'var(--text-primary)' }}>
                  <span className="w-1.5 h-1.5 rounded-full inline-block shrink-0"
                    style={{ background: c.active ? 'var(--jade)' : 'var(--border-hard)' }} />
                  <span className="flex-1 truncate">{c.id}</span>
                  {c.name && c.name !== c.id && (
                    <span className="text-[10px] truncate max-w-[120px]" style={{ color: 'var(--text-muted)' }}>{c.name}</span>
                  )}
                  {c.active && (
                    <span className="px-1 py-0.5 rounded text-[9px] font-sans shrink-0"
                      style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>
                      ACTIVE
                    </span>
                  )}
                </button>
              ))}
              {cases.length === 0 && (
                <p className="px-3 py-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                  {isExaminer ? 'No cases yet — create one to begin.' : 'No cases found'}
                </p>
              )}
              {isExaminer && (
                <button onClick={openCreate}
                  className="w-full text-left px-3 py-2 text-xs font-sans font-semibold flex items-center gap-2 hover:bg-bg-raised transition-colors border-t border-border-faint"
                  style={{ color: 'var(--cyan)' }}>
                  <Icon name="plus" className="w-3.5 h-3.5 shrink-0" />
                  New case
                </button>
              )}
            </div>
          )}
        </div>

        <div className="flex-1" />

        {/* Agent status */}
        <div className="flex items-center gap-1.5 mr-4 text-xs font-sans"
          title={agentStatusTooltip}
          style={{ color: 'var(--text-muted)', cursor: 'help' }}>
          <span className={isProcessing ? 'pulse' : ''} style={{
            width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
            background: agentStatusColor,
          }} />
          <span>{agentStatusLabel}</span>
        </div>

        {/* User */}
        <div className="flex items-center gap-2 text-xs font-sans" style={{ color: 'var(--text-muted)' }}>
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
              <span className="text-xs font-sans uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                Password <span className="normal-case text-text-ghost">(re-auth; skipped under Supabase authority)</span>
              </span>
              <input type="password" value={activatePassword}
                onChange={(e) => setActivatePassword(e.target.value)}
                className="mt-1 w-full px-3 py-2 rounded text-sm font-sans"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                autoFocus />
            </label>
            <div className="flex gap-2">
              <button type="submit" disabled={activating}
                className="flex-1 py-1.5 rounded text-xs font-sans font-semibold disabled:opacity-60 flex items-center justify-center gap-1.5"
                style={{ background: 'var(--cyan)', color: 'var(--bg-base)' }}>
                {activating && (
                  <svg className="animate-spin w-3 h-3 shrink-0" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                {activating ? 'Activating...' : 'Activate'}
              </button>
              <button type="button" disabled={activating}
                onClick={() => { setActivatingCase(null); setActivatePassword('') }}
                className="px-3 py-1.5 rounded text-xs font-sans"
                style={{ border: '1px solid var(--border-soft)', color: 'var(--text-muted)' }}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Case creation modal */}
      {creatingCase && (
        <div className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(7,9,14,0.8)' }}
          onClick={() => !creating && setCreatingCase(false)}>
          <form onSubmit={confirmCreate} onClick={(e) => e.stopPropagation()}
            className="w-96 p-6 rounded-lg space-y-4"
            style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-soft)' }}>
            <h2 className="text-sm font-sans font-semibold" style={{ color: 'var(--text-bright)' }}>
              Create new case
            </h2>
            {createErr && <p className="text-xs" style={{ color: 'var(--crimson)' }}>{createErr}</p>}
            <label className="block">
              <span className="text-xs font-sans uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                Case name <span className="normal-case">(lowercase, used for the case id)</span>
              </span>
              <input type="text" value={newCaseName}
                onChange={(e) => setNewCaseName(e.target.value)}
                placeholder="e.g. rocba"
                className="mt-1 w-full px-3 py-2 rounded text-sm font-mono"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                autoFocus required />
            </label>
            <label className="block">
              <span className="text-xs font-sans uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Title</span>
              <input type="text" value={newCaseTitle}
                onChange={(e) => setNewCaseTitle(e.target.value)}
                placeholder="e.g. ROCBA intrusion investigation"
                className="mt-1 w-full px-3 py-2 rounded text-sm font-sans"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                required />
            </label>
            <label className="block">
              <span className="text-xs font-sans uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                Synopsis <span className="normal-case">(optional — case scope/background for the brief)</span>
              </span>
              <textarea value={newCaseSynopsis}
                onChange={(e) => setNewCaseSynopsis(e.target.value)}
                placeholder="Short narrative: what happened, the in-scope system(s), and the investigative objectives."
                rows={4}
                className="mt-1 w-full px-3 py-2 rounded text-sm font-sans resize-y"
                style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }} />
            </label>
            <div className="flex gap-2">
              <button type="submit" disabled={creating}
                className="flex-1 py-1.5 rounded text-xs font-sans font-semibold disabled:opacity-60 flex items-center justify-center gap-1.5"
                style={{ background: 'var(--cyan)', color: 'var(--bg-base)' }}>
                {creating && (
                  <svg className="animate-spin w-3 h-3 shrink-0" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                {creating ? 'Creating...' : 'Create case'}
              </button>
              <button type="button" disabled={creating}
                onClick={() => setCreatingCase(false)}
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
