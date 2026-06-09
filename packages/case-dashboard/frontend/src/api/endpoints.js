import { apiFetch, apiPost, apiPatch, apiDelete, LONG_TIMEOUT_MS } from './client'

const REAUTH_OPTS = { suppressUnauthorized: true }
// Re-auth + long timeout for operations that hash mounted evidence bytes
// synchronously (seal / proof-export / verify / delete) — large disk/memory
// images can take minutes, well past the default 15s client timeout.
const REAUTH_HASH_OPTS = { suppressUnauthorized: true, timeoutMs: LONG_TIMEOUT_MS }

// --- Auth ---
export const getSetupRequired = () => apiFetch('/api/auth/setup-required')
export const postSetup = (body) => apiPost('/api/auth/setup', body)
export const getChallenge = (examiner) => apiFetch('/api/auth/challenge?examiner=' + encodeURIComponent(examiner))
export const postLogin = (body) => apiPost('/api/auth/login', body)
export const postLogout = () => apiPost('/api/auth/logout', {})
export const postResetPassword = (body) => apiPost('/api/auth/reset-password', body)
export const getMe = () => apiFetch('/api/auth/me')

// --- PR03A: Supabase email/password login + agent/service principals ---
// Supabase login posts { email, password }; the server sets the signed session
// envelope cookie. No token material is ever returned, displayed, or stored.
export const postSupabaseLogin = (body) => apiPost('/api/auth/login', body)
export const postAuthRefresh = () => apiPost('/api/auth/refresh', {})
export const getPrincipals = () => apiFetch('/api/auth/principals')
export const postPrincipal = (body) => apiPost('/api/auth/principals', body)
export const deletePrincipal = (type, id) => apiDelete(`/api/auth/principals/${type}/${id}`)

// --- Cases ---
export const getCases = () => apiFetch('/api/cases')
export const postCaseCreate = (body) => apiPost('/api/case/create', body)
export const getCaseActivateChallenge = () => apiFetch('/api/case/activate/challenge')
export const postCaseActivate = (body) => apiPost('/api/case/activate', body, REAUTH_OPTS)
export const getCase = () => apiFetch('/api/case')
export const postCaseMetadata = (body) => apiPost('/api/case/metadata', body)

// --- Investigation data ---
export const getFindings = () => apiFetch('/api/findings')
export const getFinding = (id) => apiFetch(`/api/findings/${id}`)
export const getTimeline = () => apiFetch('/api/timeline')
export const getEvidence = () => apiFetch('/api/evidence')
export const getIocs = () => apiFetch('/api/iocs')
export const getTodos = () => apiFetch('/api/todos')
export const createTodo = (body) => apiPost('/api/todos', body)
export const updateTodo = (id, body) => apiPatch(`/api/todos/${id}`, body)
export const deleteTodo = (id) => apiDelete(`/api/todos/${id}`)
export const getSummary = () => apiFetch('/api/summary')
export const getAudit = (findingId) => apiFetch(`/api/audit/${findingId}`)

// --- Delta (review workflow) ---
export const getDelta = () => apiFetch('/api/delta')
export const postDelta = (body) => apiPost('/api/delta', body)
export const deleteDelta = (id) => apiDelete(`/api/delta/${id}`)
export const getCommitChallenge = () => apiFetch('/api/commit/challenge')
export const postCommit = (body) => apiPost('/api/commit', body, REAUTH_OPTS)

// --- Evidence chain ---
export const getChainStatus = () => apiFetch('/api/evidence/chain/status')
export const postChainRescan = () => apiPost('/api/evidence/chain/rescan', {})
export const getChainChallenge = () => apiFetch('/api/evidence/chain/challenge')
export const postChainSeal = (body) => apiPost('/api/evidence/chain/seal', body, REAUTH_HASH_OPTS)
export const postChainAnchor = (body) => apiPost('/api/evidence/chain/anchor', body)
export const postChainProofExport = (body) => apiPost('/api/evidence/chain/proof-export', body, { timeoutMs: LONG_TIMEOUT_MS })
export const postChainVerifyHmac = (body) => apiPost('/api/evidence/chain/verify-hmac', body, REAUTH_HASH_OPTS)
export const postVerifyEvidence = (path) => apiPost(`/api/evidence/${encodeURIComponent(path)}/verify`, {})
export const postChainIgnore = (body) => apiPost('/api/evidence/chain/ignore', body, REAUTH_OPTS)
export const postChainDelete = (body) => apiPost('/api/evidence/chain/delete', body, REAUTH_HASH_OPTS)
export const postChainRetire = (body) => apiPost('/api/evidence/chain/retire', body, REAUTH_OPTS)

// --- Response guard ---
export const getResponseGuardStatus = () => apiFetch('/api/response-guard/status')
export const postResponseGuardOverride = (body = {}) => apiPost('/api/response-guard/override', body, REAUTH_OPTS)
export const postResponseGuardOverrideCancel = () => apiPost('/api/response-guard/override/cancel', {})

// --- Agent tokens ---
export const getTokens = () => apiFetch('/api/tokens')
export const postToken = (body) => apiPost('/api/tokens', body)
export const deleteToken = (id) => apiDelete(`/api/tokens/${id}`)
export const postRotateToken = (id) => apiPost(`/api/tokens/${id}/rotate`, {})
export const postReactivateToken = (id) => apiPost(`/api/tokens/${id}/reactivate`, {})

// --- Reports ---
export const getReports = () => apiFetch('/api/reports')
export const getReportChallenge = () => apiFetch('/api/reports/challenge')
export const postReportGenerate = (body) => apiPost('/api/reports/generate', body, REAUTH_OPTS)
export const postReportSave = (id) => apiPost(`/api/reports/${id}/save`, {})
export const getReport = (id) => apiFetch(`/api/reports/${id}`)
export const downloadReport = (id) => apiFetch(`/api/reports/${id}/download`)

// --- Portal state (DB authority: seal/custody/add-on/report eligibility) ---
export const getPortalState = () => apiFetch('/api/portal/state')

// --- Jobs (D2 Gateway job/status adapter) ---
export const getJobStatus = (jobId) => apiFetch(`/api/jobs/${encodeURIComponent(jobId)}`)

// --- Backends & Services ---
export const getBackends = () => apiFetch('/api/backends')
export const postRegisterBackend = (body) => apiPost('/api/backends', body)
export const deleteBackend = (name, body) => apiDelete(`/api/backends/${encodeURIComponent(name)}`, body)
export const postValidateBackend = (body) => apiPost('/api/backends/validate', body)
export const postReloadBackends = (body) => apiPost('/api/backends/reload', body)
export const postStartService = (name, body) => apiPost(`/api/services/${name}/start`, body)
export const postStopService = (name, body) => apiPost(`/api/services/${name}/stop`, body)
export const postRestartService = (name, body) => apiPost(`/api/services/${name}/restart`, body)
