import { useCallback, useEffect, useState } from 'react'

import {
  getBackends,
  deleteBackend,
  postRegisterBackend,
  postValidateBackend,
  postReloadBackends,
  postStartService,
  postStopService,
  postRestartService,
  postSetBackendEnabled,
} from '@/api/endpoints'
import { buildConfigPayload } from './backends-utils'

// useBackends — owns the registry list + register-form state + every mutating
// admin action (register · validate · reload · start · stop · restart ·
// unregister · enable-toggle), each wrapped in the password challenge. Keeps
// BackendsTab a thin orchestrator. Mock/real split is at the API adapter layer.

const EMPTY_FORM = {
  type: 'stdio', name: '', manifestPath: '', command: '', argsStr: '',
  envList: [{ key: '', value: '' }], url: '', bearerTokenEnv: '', tlsCertEnv: '',
}

export function useBackends({ addToast, openChallenge }) {
  const [backends, setBackends] = useState([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState(EMPTY_FORM)
  const [validating, setValidating] = useState(false)
  const [validationResult, setValidationResult] = useState(null)

  const fetchBackends = useCallback(async () => {
    setLoading(true)
    try {
      const res = await getBackends()
      setBackends(res?.backends || [])
    } catch (err) {
      addToast(err.message || 'Failed to load backends', 'error')
    } finally {
      setLoading(false)
    }
  }, [addToast])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchBackends()
  }, [fetchBackends])

  const setField = useCallback((field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }))
  }, [])

  const envActions = {
    add: () => setForm((prev) => ({ ...prev, envList: [...prev.envList, { key: '', value: '' }] })),
    update: (index, field, value) =>
      setForm((prev) => ({
        ...prev,
        envList: prev.envList.map((row, i) => (i === index ? { ...row, [field]: value } : row)),
      })),
    remove: (index) =>
      setForm((prev) => ({ ...prev, envList: prev.envList.filter((_, i) => i !== index) })),
  }

  async function handleValidate() {
    if (!form.name.trim()) return addToast('Backend name is required', 'warn')
    setValidating(true)
    setValidationResult(null)
    try {
      const res = await postValidateBackend({ name: form.name.trim(), config: buildConfigPayload(form) })
      setValidationResult(res)
      addToast(res.valid ? 'Validation succeeded' : 'Validation failed', res.valid ? 'success' : 'error')
    } catch (err) {
      setValidationResult(
        err.reasons
          ? { valid: false, reasons: err.reasons }
          : { valid: false, reasons: [{ field: 'general', reason: err.message || 'Validation request failed' }] },
      )
      addToast(err.message || 'Validation failed', 'error')
    } finally {
      setValidating(false)
    }
  }

  function handleRegister() {
    if (!form.name.trim()) return addToast('Backend name is required', 'warn')
    openChallenge('Verify Password to Register Backend', async (params) => {
      const res = await postRegisterBackend({ name: form.name.trim(), config: buildConfigPayload(form), ...params })
      addToast(res.restart_required ? 'Backend registered; Gateway restart required' : 'Backend registered successfully', 'success')
      setForm(EMPTY_FORM)
      setValidationResult(null)
      await fetchBackends()
    })
  }

  function handleReload() {
    openChallenge('Verify Password to Check Apply Status', async (params) => {
      const res = await postReloadBackends(params)
      addToast(res.restart_required ? 'Registry changes pending Gateway restart' : `Registry status: ${res.status || 'current'}`, res.restart_required ? 'warn' : 'success')
      await fetchBackends()
    })
  }

  const lifecycle = (title, call, done) => (name) =>
    openChallenge(`${title}: ${name}`, async (params) => {
      await call(name, params)
      addToast(done(name), 'success')
      await fetchBackends()
    })

  const handleStart = lifecycle('Start Service', postStartService, (n) => `Service ${n} started`)
  const handleStop = lifecycle('Stop Service', postStopService, (n) => `Service ${n} stopped`)
  const handleRestart = lifecycle('Restart Service', postRestartService, (n) => `Service ${n} restarted`)

  function handleUnregister(name) {
    openChallenge(`Unregister Backend: ${name}`, async (params) => {
      const res = await deleteBackend(name, params)
      addToast(res.restart_required ? 'Backend unregistered; Gateway restart required' : 'Backend unregistered', res.restart_required ? 'warn' : 'success')
      await fetchBackends()
    })
  }

  function handleToggleEnabled(name, nextEnabled) {
    openChallenge(`${nextEnabled ? 'Enable' : 'Disable'} Backend: ${name}`, async (params) => {
      const res = await postSetBackendEnabled(name, { enabled: nextEnabled, ...params })
      const verb = nextEnabled ? 'enabled' : 'disabled'
      addToast(res.restart_required ? `Backend ${verb}; Gateway restart required` : `Backend ${verb}`, res.restart_required ? 'warn' : 'success')
      await fetchBackends()
    })
  }

  return {
    backends,
    loading,
    form,
    setField,
    envActions,
    validating,
    validationResult,
    handleValidate,
    handleRegister,
    handleReload,
    handleStart,
    handleStop,
    handleRestart,
    handleUnregister,
    handleToggleEnabled,
  }
}
