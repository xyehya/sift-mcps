import { useState, useEffect } from 'react'
import {
  getBackends,
  postRegisterBackend,
  postValidateBackend,
  postReloadBackends,
  postStartService,
  postStopService,
  postRestartService,
  getCommitChallenge
} from '../../api/endpoints'
import { computeSimpleChallengeResponse } from '../../api/crypto'
import { useStore } from '../../store/useStore'

export function BackendsTab() {
  const { addToast } = useStore()
  const [backends, setBackends] = useState([])
  const [loading, setLoading] = useState(false)
  const [validationResult, setValidationResult] = useState(null)
  const [validating, setValidating] = useState(false)

  // Form State
  const [type, setType] = useState('stdio') // stdio or http
  const [name, setName] = useState('')
  const [manifestPath, setManifestPath] = useState('')
  // stdio specific
  const [command, setCommand] = useState('')
  const [argsStr, setArgsStr] = useState('')
  const [envList, setEnvList] = useState([{ key: '', value: '' }])
  // http specific
  const [url, setUrl] = useState('')
  const [bearerToken, setBearerToken] = useState('')
  const [tlsCert, setTlsCert] = useState('')

  // Challenge Modal State
  const [challengeModal, setChallengeModal] = useState({
    isOpen: false,
    title: '',
    error: '',
    loading: false,
    password: '',
    onConfirm: null
  })

  useEffect(() => {
    fetchBackends()
  }, [])

  async function fetchBackends() {
    setLoading(true)
    try {
      const res = await getBackends()
      setBackends(res.backends || [])
    } catch (err) {
      addToast(err.message || 'Failed to load backends', 'error')
    } finally {
      setLoading(false)
    }
  }

  // Build the payload config
  function buildConfigPayload() {
    const config = { type, manifest_path: manifestPath }
    if (type === 'stdio') {
      config.command = command
      // Args parsing: JSON array or newline-separated
      let parsedArgs = []
      const trimmedArgs = argsStr.trim()
      if (trimmedArgs) {
        if (trimmedArgs.startsWith('[') && trimmedArgs.endsWith(']')) {
          try {
            parsedArgs = JSON.parse(trimmedArgs)
            if (!Array.isArray(parsedArgs)) {
              throw new Error('Args JSON must be an array')
            }
          } catch (e) {
            parsedArgs = trimmedArgs.split('\n').map(a => a.trim()).filter(Boolean)
          }
        } else {
          parsedArgs = trimmedArgs.split('\n').map(a => a.trim()).filter(Boolean)
        }
      }
      config.args = parsedArgs

      // Environment variables compiler
      const envObj = {}
      envList.forEach(({ key, value }) => {
        if (key.trim()) {
          envObj[key.trim()] = value
        }
      })
      config.env = envObj
    } else {
      config.url = url
      if (bearerToken) config.bearer_token = bearerToken
      if (tlsCert) config.tls_cert = tlsCert
    }
    return config
  }

  async function handleValidate(e) {
    if (e) e.preventDefault()
    if (!name.trim()) {
      addToast('Backend name is required', 'warn')
      return
    }
    setValidating(true)
    setValidationResult(null)
    try {
      const payload = {
        name: name.trim(),
        config: buildConfigPayload()
      }
      const res = await postValidateBackend(payload)
      setValidationResult(res)
      if (res.valid) {
        addToast('Validation succeeded', 'success')
      } else {
        addToast('Validation failed', 'error')
      }
    } catch (err) {
      // In case route returns 422 with validation errors
      if (err.reasons) {
        setValidationResult({ valid: false, reasons: err.reasons })
      } else {
        setValidationResult({ valid: false, reasons: [{ field: 'general', reason: err.message || 'Validation request failed' }] })
      }
      addToast(err.message || 'Validation failed', 'error')
    } finally {
      setValidating(false)
    }
  }

  function openChallenge(title, onConfirm) {
    setChallengeModal({
      isOpen: true,
      title,
      error: '',
      loading: false,
      password: '',
      onConfirm
    })
  }

  async function submitChallenge(e) {
    e.preventDefault()
    const { password, onConfirm } = challengeModal
    if (!password) return

    setChallengeModal(prev => ({ ...prev, loading: true, error: '' }))
    try {
      const challenge = await getCommitChallenge()
      const response = await computeSimpleChallengeResponse(password, challenge)
      await onConfirm({ challenge_id: challenge.challenge_id, response })
      setChallengeModal({
        isOpen: false,
        title: '',
        error: '',
        loading: false,
        password: '',
        onConfirm: null
      })
    } catch (err) {
      setChallengeModal(prev => ({
        ...prev,
        loading: false,
        error: err.message || 'Password verification failed'
      }))
    }
  }

  function handleRegisterClick(e) {
    e.preventDefault()
    if (!name.trim()) {
      addToast('Backend name is required', 'warn')
      return
    }
    openChallenge('Verify Password to Register Backend', async (challengeParams) => {
      const payload = {
        name: name.trim(),
        config: buildConfigPayload(),
        ...challengeParams
      }
      await postRegisterBackend(payload)
      addToast('Backend registered successfully', 'success')
      // Reset form
      setName('')
      setManifestPath('')
      setCommand('')
      setArgsStr('')
      setEnvList([{ key: '', value: '' }])
      setUrl('')
      setBearerToken('')
      setTlsCert('')
      setValidationResult(null)
      await fetchBackends()
    })
  }

  function handleReloadClick() {
    openChallenge('Verify Password to Reload Configurations', async (challengeParams) => {
      const res = await postReloadBackends(challengeParams)
      addToast(`Configuration reload completed: ${res.status || 'success'}`, 'success')
      await fetchBackends()
    })
  }

  function handleStart(bName) {
    openChallenge(`Start Service: ${bName}`, async (challengeParams) => {
      await postStartService(bName, challengeParams)
      addToast(`Service ${bName} started`, 'success')
      await fetchBackends()
    })
  }

  function handleStop(bName) {
    openChallenge(`Stop Service: ${bName}`, async (challengeParams) => {
      await postStopService(bName, challengeParams)
      addToast(`Service ${bName} stopped`, 'success')
      await fetchBackends()
    })
  }

  function handleRestart(bName) {
    openChallenge(`Restart Service: ${bName}`, async (challengeParams) => {
      await postRestartService(bName, challengeParams)
      addToast(`Service ${bName} restarted`, 'success')
      await fetchBackends()
    })
  }

  const updateEnv = (index, field, val) => {
    const next = [...envList]
    next[index][field] = val
    setEnvList(next)
  }

  const addEnvRow = () => {
    setEnvList([...envList, { key: '', value: '' }])
  }

  const removeEnvRow = (index) => {
    setEnvList(envList.filter((_, idx) => idx !== index))
  }

  return (
    <div className="h-full overflow-y-auto p-5 space-y-6" style={{ background: 'var(--bg-base)' }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="font-display font-bold text-lg text-text-bright">Backends & Add-ons</h1>
        <button
          onClick={handleReloadClick}
          className="px-3 py-1.5 rounded text-xs font-semibold hover:opacity-85 border transition-opacity flex items-center gap-1.5"
          style={{ background: 'var(--amber-dim)', color: 'var(--amber)', borderColor: 'var(--amber)' }}
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 7.89M9 11l3-3m0 0l3 3m-3-3v12" />
          </svg>
          Reload Config
        </button>
      </div>

      {/* Grid container */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        
        {/* Left/Main Column: Configured Backends Panel */}
        <div className="lg:col-span-2 p-4 rounded border flex flex-col"
          style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
          <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
            CONFIGURED BACKENDS
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--border-soft)' }}>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">NAME</th>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">TYPE</th>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">STATUS</th>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">HEALTH</th>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px]">REQUIREMENTS</th>
                  <th className="py-2.5 font-semibold text-text-muted font-mono text-[10px] text-right">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="6" className="py-8 text-center text-text-muted font-mono animate-pulse">Loading configured backends…</td>
                  </tr>
                ) : backends.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="py-8 text-center text-text-muted font-mono">No configured backends found.</td>
                  </tr>
                ) : (
                  backends.map((b) => {
                    const healthStatus = b.health?.status || 'unknown';
                    const hasUnmet = b.unmet_requires && b.unmet_requires.length > 0;

                    // Button enablement rules
                    const canStart = b.enabled && !b.started && !hasUnmet;
                    const canStop = b.started; // Stop is allowed if started, even if disabled or gated
                    const canRestart = b.enabled && b.started && !hasUnmet;

                    return (
                      <tr key={b.name} className="border-b" style={{ borderColor: 'var(--border-faint)' }}>
                        <td className="py-3 font-mono font-semibold text-text-bright">{b.name}</td>
                        <td className="py-3 font-mono text-text-muted text-[11px]">{b.type}</td>
                        <td className="py-3">
                          {b.enabled ? (
                            <span className="px-1.5 py-0.5 rounded font-mono text-[9px] font-semibold"
                                  style={{ backgroundColor: 'var(--jade-dim)', color: 'var(--jade)' }}>
                              ENABLED
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded font-mono text-[9px] font-semibold"
                                  style={{ backgroundColor: 'var(--bg-raised)', color: 'var(--text-muted)' }}>
                              DISABLED
                            </span>
                          )}
                          <span className="ml-2 font-sans text-xs">
                            {b.started ? (
                              <span style={{ color: 'var(--jade)' }}>Started</span>
                            ) : (
                              <span style={{ color: 'var(--text-muted)' }}>Stopped</span>
                            )}
                          </span>
                        </td>
                        <td className="py-3">
                          {healthStatus === 'ok' && (
                            <span className="font-mono text-xs font-semibold" style={{ color: 'var(--jade)' }}>OK</span>
                          )}
                          {healthStatus === 'disabled' && (
                            <span className="font-mono text-xs text-text-muted">Disabled</span>
                          )}
                          {healthStatus === 'gated' && (
                            <span className="font-mono text-xs font-semibold" style={{ color: 'var(--amber)' }} title={b.health?.detail || ''}>Gated</span>
                          )}
                          {healthStatus === 'invalid_manifest' && (
                            <span className="font-mono text-xs font-semibold" style={{ color: 'var(--crimson)' }} title={b.health?.detail || ''}>Invalid Manifest</span>
                          )}
                          {healthStatus !== 'ok' && healthStatus !== 'disabled' && healthStatus !== 'gated' && healthStatus !== 'invalid_manifest' && (
                            <span className="font-mono text-xs text-text-muted" title={b.health?.detail || ''}>{healthStatus}</span>
                          )}
                        </td>
                        <td className="py-3 text-xs leading-relaxed max-w-[200px]">
                          {hasUnmet ? (
                            <span className="font-semibold" style={{ color: 'var(--crimson)' }}>
                              Unmet: {b.unmet_requires.join(', ')}
                            </span>
                          ) : b.requires && b.requires.length > 0 ? (
                            <span className="text-text-muted">
                              Requires: {b.requires.join(', ')}
                            </span>
                          ) : (
                            <span className="text-text-muted italic">None</span>
                          )}
                        </td>
                        <td className="py-3 text-right space-x-1.5">
                          <button
                            onClick={() => handleStart(b.name)}
                            disabled={!canStart}
                            className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85 disabled:opacity-40 disabled:cursor-not-allowed transition-opacity"
                            style={canStart ? { background: 'var(--jade-dim)', color: 'var(--jade)', borderColor: 'var(--jade)' } : {}}
                          >
                            Start
                          </button>
                          <button
                            onClick={() => handleStop(b.name)}
                            disabled={!canStop}
                            className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85 disabled:opacity-40 disabled:cursor-not-allowed transition-opacity"
                            style={canStop ? { background: 'var(--crimson-dim)', color: 'var(--crimson)', borderColor: 'var(--crimson)' } : {}}
                          >
                            Stop
                          </button>
                          <button
                            onClick={() => handleRestart(b.name)}
                            disabled={!canRestart}
                            className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85 disabled:opacity-40 disabled:cursor-not-allowed transition-opacity"
                            style={canRestart ? { background: 'var(--amber-dim)', color: 'var(--amber)', borderColor: 'var(--amber)' } : {}}
                          >
                            Restart
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

        {/* Right Column: Add Backend Panel */}
        <div className="lg:col-span-1 space-y-6">
          <div className="p-4 rounded border flex flex-col"
            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
            <p className="text-[10px] font-sans font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>
              REGISTER NEW BACKEND
            </p>

            <form className="space-y-4">
              <div>
                <label className="block text-[10px] font-mono text-text-muted mb-1">TRANSPORT TYPE</label>
                <select
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none cursor-pointer"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                >
                  <option value="stdio">stdio (Local Subprocess)</option>
                  <option value="http">http (Remote/Local HTTP Endpoint)</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] font-mono text-text-muted mb-1">BACKEND NAME *</label>
                <input
                  type="text"
                  placeholder="e.g. windows-triage-mcp"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                />
              </div>

              <div>
                <label className="block text-[10px] font-mono text-text-muted mb-1">MANIFEST PATH / URL</label>
                <input
                  type="text"
                  placeholder="e.g. packages/windows-triage-mcp/sift-backend.json or http://..."
                  value={manifestPath}
                  onChange={(e) => setManifestPath(e.target.value)}
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                />
              </div>

              {type === 'stdio' ? (
                <>
                  <div>
                    <label className="block text-[10px] font-mono text-text-muted mb-1">COMMAND *</label>
                    <input
                      type="text"
                      placeholder="e.g. node or python"
                      value={command}
                      onChange={(e) => setCommand(e.target.value)}
                      required={type === 'stdio'}
                      className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                      style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] font-mono text-text-muted mb-1">ARGUMENTS (One per line or JSON Array)</label>
                    <textarea
                      placeholder="e.g.&#10;--verbose&#10;--port&#10;8080&#10;or [&#34;--verbose&#34;, &#34;--port&#34;, &#34;8080&#34;]"
                      value={argsStr}
                      onChange={(e) => setArgsStr(e.target.value)}
                      rows={3}
                      className="w-full px-3 py-2 rounded text-xs font-mono focus:outline-none resize-none"
                      style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="block text-[10px] font-mono text-text-muted">ENVIRONMENT VARIABLES</label>
                      <button
                        type="button"
                        onClick={addEnvRow}
                        className="text-[10px] text-cyan hover:underline font-semibold"
                      >
                        + Add Row
                      </button>
                    </div>
                    <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
                      {envList.map((row, index) => (
                        <div key={index} className="flex gap-2 items-center">
                          <input
                            type="text"
                            placeholder="Key"
                            value={row.key}
                            onChange={(e) => updateEnv(index, 'key', e.target.value)}
                            className="w-1/2 px-2 py-1 rounded text-xs focus:outline-none"
                            style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                          />
                          <input
                            type="text"
                            placeholder="Value"
                            value={row.value}
                            onChange={(e) => updateEnv(index, 'value', e.target.value)}
                            className="w-1/2 px-2 py-1 rounded text-xs focus:outline-none"
                            style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                          />
                          <button
                            type="button"
                            onClick={() => removeEnvRow(index)}
                            className="text-text-muted hover:text-crimson font-bold text-sm px-1"
                          >
                            &times;
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <label className="block text-[10px] font-mono text-text-muted mb-1">URL *</label>
                    <input
                      type="url"
                      placeholder="e.g. http://localhost:8080/mcp"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      required={type === 'http'}
                      className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                      style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] font-mono text-text-muted mb-1">BEARER TOKEN</label>
                    <input
                      type="password"
                      placeholder="OAuth/Bearer authentication token"
                      value={bearerToken}
                      onChange={(e) => setBearerToken(e.target.value)}
                      className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                      style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] font-mono text-text-muted mb-1">TLS CERT PATH</label>
                    <input
                      type="text"
                      placeholder="Path to TLS certificate file"
                      value={tlsCert}
                      onChange={(e) => setTlsCert(e.target.value)}
                      className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                      style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                    />
                  </div>
                </>
              )}

              <div className="grid grid-cols-2 gap-3 pt-2">
                <button
                  type="button"
                  onClick={handleValidate}
                  disabled={validating}
                  className="py-2 rounded text-xs font-sans font-semibold hover:opacity-85 border transition-all flex items-center justify-center gap-1.5"
                  style={{ background: 'var(--bg-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-soft)' }}
                >
                  {validating && (
                    <svg className="animate-spin h-3.5 w-3.5 text-text-primary" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                  Validate
                </button>
                <button
                  type="button"
                  onClick={handleRegisterClick}
                  className="py-2 rounded text-xs font-sans font-semibold hover:opacity-85 border transition-opacity"
                  style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)', borderColor: 'var(--cyan)' }}
                >
                  Register
                </button>
              </div>
            </form>
          </div>

          {/* Validation Results Display */}
          {validationResult && (
            <div className="p-4 rounded border text-xs font-sans space-y-3"
                 style={{
                   background: validationResult.valid ? 'var(--jade-dim)' : 'var(--crimson-dim)',
                   borderColor: validationResult.valid ? 'var(--jade)' : 'var(--crimson)',
                   color: 'var(--text-bright)'
                 }}>
              <div className="font-bold flex items-center gap-1.5">
                {validationResult.valid ? (
                  <>
                    <svg className="w-4 h-4 text-jade" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    VALID BACKEND MANIFEST
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4 text-crimson" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    VALIDATION ERROR
                  </>
                )}
              </div>

              {validationResult.valid ? (
                <div className="space-y-2">
                  <div>
                    <span className="font-mono text-[10px] text-text-muted uppercase block">Namespace</span>
                    <span className="font-mono font-semibold">{validationResult.namespace}</span>
                  </div>

                  <div>
                    <span className="font-mono text-[10px] text-text-muted uppercase block">Provides Capabilities</span>
                    <span>{validationResult.provides?.join(', ') || 'none'}</span>
                  </div>

                  <div>
                    <span className="font-mono text-[10px] text-text-muted uppercase block">Requirements</span>
                    {validationResult.unmet_requires?.length > 0 ? (
                      <span style={{ color: 'var(--crimson)' }} className="font-semibold">
                        Unmet: {validationResult.unmet_requires.join(', ')}
                      </span>
                    ) : (
                      <span className="text-text-muted">
                        {validationResult.requires?.join(', ') || 'none'} (all met)
                      </span>
                    )}
                  </div>

                  {validationResult.tools && validationResult.tools.length > 0 && (
                    <div>
                      <span className="font-mono text-[10px] text-text-muted uppercase block">Registered Tools ({validationResult.tools.length})</span>
                      <ul className="list-disc list-inside space-y-1 font-mono text-[11px] mt-1 max-h-[120px] overflow-y-auto pl-1">
                        {validationResult.tools.map((t, idx) => (
                          <li key={idx} title={t.description || ''}>{t.name}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {validationResult.instructions && (
                    <div>
                      <span className="font-mono text-[10px] text-text-muted uppercase block">Instructions</span>
                      <p className="bg-bg-raised/40 p-2 rounded text-[11px] font-mono leading-relaxed max-h-[100px] overflow-y-auto mt-1 whitespace-pre-wrap">
                        {validationResult.instructions}
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <ul className="list-disc list-inside space-y-1 font-mono text-[11px] leading-relaxed">
                  {validationResult.reasons?.map((r, i) => (
                    <li key={i}>
                      <strong className="text-text-bright">{r.field}:</strong> {r.reason}
                    </li>
                  )) || <li>Unknown validation error occurred</li>}
                </ul>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Password Challenge Dialog */}
      {challengeModal.isOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
          <div className="w-[360px] p-5 rounded-lg border shadow-xl flex flex-col gap-4 animate-scale-up"
               style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-soft)' }}>
            
            <div className="flex items-center justify-between">
              <h3 className="font-display font-bold text-sm text-text-bright">{challengeModal.title}</h3>
              <button
                onClick={() => setChallengeModal(prev => ({ ...prev, isOpen: false }))}
                className="text-text-muted hover:text-text-bright font-bold text-lg leading-none"
              >
                &times;
              </button>
            </div>

            <p className="text-xs text-text-muted leading-relaxed">
              Confirm your password to authorize this mutating admin action.
            </p>

            <form onSubmit={submitChallenge} className="space-y-4">
              <div>
                <input
                  type="password"
                  placeholder="Enter examiner password"
                  value={challengeModal.password}
                  onChange={(e) => setChallengeModal(prev => ({ ...prev, password: e.target.value }))}
                  required
                  autoFocus
                  className="w-full px-3 py-2 rounded text-xs focus:outline-none"
                  style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-bright)' }}
                />
              </div>

              {challengeModal.error && (
                <p className="text-xs font-mono" style={{ color: 'var(--crimson)' }}>
                  ⚠️ {challengeModal.error}
                </p>
              )}

              <div className="flex justify-end gap-2.5 pt-1">
                <button
                  type="button"
                  onClick={() => setChallengeModal(prev => ({ ...prev, isOpen: false }))}
                  className="px-3 py-1.5 rounded text-xs font-semibold hover:bg-bg-raised text-text-muted transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={challengeModal.loading || !challengeModal.password}
                  className="px-3 py-1.5 rounded text-xs font-semibold hover:opacity-85 border transition-all flex items-center gap-1.5"
                  style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)', borderColor: 'var(--cyan)' }}
                >
                  {challengeModal.loading && (
                    <svg className="animate-spin h-3.5 w-3.5 text-cyan" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                  )}
                  Confirm
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
