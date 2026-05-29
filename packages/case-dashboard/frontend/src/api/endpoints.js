import { apiFetch, apiPost, apiDelete } from './client'

// --- Auth ---
export const getSetupRequired = () => apiFetch('/api/auth/setup-required')
export const postSetup = (body) => apiPost('/api/auth/setup', body)
export const getChallenge = (examiner) => apiFetch('/api/auth/challenge?examiner=' + encodeURIComponent(examiner))
export const postLogin = (body) => apiPost('/api/auth/login', body)
export const postLogout = () => apiPost('/api/auth/logout', {})
export const postResetPassword = (body) => apiPost('/api/auth/reset-password', body)
export const getMe = () => apiFetch('/api/auth/me')

// --- Cases ---
export const getCases = () => apiFetch('/api/cases')
export const postCaseCreate = (body) => apiPost('/api/case/create', body)
export const getCaseActivateChallenge = () => apiFetch('/api/case/activate/challenge')
export const postCaseActivate = (body) => apiPost('/api/case/activate', body)
export const getCase = () => apiFetch('/api/case')

// --- Investigation data ---
export const getFindings = () => apiFetch('/api/findings')
export const getFinding = (id) => apiFetch(`/api/findings/${id}`)
export const getTimeline = () => apiFetch('/api/timeline')
export const getEvidence = () => apiFetch('/api/evidence')
export const getIocs = () => apiFetch('/api/iocs')
export const getTodos = () => apiFetch('/api/todos')
export const getSummary = () => apiFetch('/api/summary')
export const getAudit = (findingId) => apiFetch(`/api/audit/${findingId}`)

// --- Delta (review workflow) ---
export const getDelta = () => apiFetch('/api/delta')
export const postDelta = (body) => apiPost('/api/delta', body)
export const deleteDelta = (id) => apiDelete(`/api/delta/${id}`)
export const getCommitChallenge = () => apiFetch('/api/commit/challenge')
export const postCommit = (body) => apiPost('/api/commit', body)

// --- Evidence chain ---
export const getChainStatus = () => apiFetch('/api/evidence/chain/status')
export const postChainRescan = () => apiPost('/api/evidence/chain/rescan', {})
export const getChainChallenge = () => apiFetch('/api/evidence/chain/challenge')
export const postChainSeal = (body) => apiPost('/api/evidence/chain/seal', body)
export const postChainAnchor = (body) => apiPost('/api/evidence/chain/anchor', body)
export const postChainVerifyHmac = (body) => apiPost('/api/evidence/chain/verify-hmac', body)
export const postVerifyEvidence = (path) => apiPost(`/api/evidence/${path}/verify`, {})
export const postChainIgnore = (body) => apiPost('/api/evidence/chain/ignore', body)
export const postChainRetire = (body) => apiPost('/api/evidence/chain/retire', body)

// --- Response guard ---
export const getResponseGuardStatus = () => apiFetch('/api/response-guard/status')
export const postResponseGuardOverride = () => apiPost('/api/response-guard/override', {})
export const postResponseGuardOverrideCancel = () => apiPost('/api/response-guard/override/cancel', {})

// --- Agent tokens ---
export const getTokens = () => apiFetch('/api/tokens')
export const postToken = (body) => apiPost('/api/tokens', body)
export const deleteToken = (id) => apiDelete(`/api/tokens/${id}`)
export const postRotateToken = (id) => apiPost(`/api/tokens/${id}/rotate`, {})
export const postReactivateToken = (id) => apiPost(`/api/tokens/${id}/reactivate`, {})

// --- Reports ---
export const getReports = () => apiFetch('/api/reports')
export const postReportGenerate = (body) => apiPost('/api/reports/generate', body)
export const postReportSave = (id) => apiPost(`/api/reports/${id}/save`, {})
export const getReport = (id) => apiFetch(`/api/reports/${id}`)
export const downloadReport = (id) => apiFetch(`/api/reports/${id}/download`)
