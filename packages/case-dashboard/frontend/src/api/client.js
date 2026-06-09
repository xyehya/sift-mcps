const BASE = '/portal'
const TIMEOUT_MS = 15000

// Emitted when any request returns 401 — App listens to redirect to login
const LOGIN_EVENT = 'sift:unauthorized'

export function emitUnauthorized() {
  window.dispatchEvent(new Event(LOGIN_EVENT))
}

export function onUnauthorized(cb) {
  window.addEventListener(LOGIN_EVENT, cb)
  return () => window.removeEventListener(LOGIN_EVENT, cb)
}

async function responseError(res) {
  const text = await res.text().catch(() => res.statusText)
  let message = text || `HTTP ${res.status}`
  try {
    const parsed = JSON.parse(text)
    if (parsed && typeof parsed.error === 'string') message = parsed.error
  } catch {
    // Keep the raw response text when it is not JSON.
  }
  const err = new Error(message)
  err.status = res.status
  return err
}

export async function apiFetch(path, opts = {}) {
  const controller = new AbortController()
  const tid = setTimeout(() => controller.abort(), TIMEOUT_MS)

  const { suppressUnauthorized = false, ...fetchOpts } = opts
  const headers = { 'Content-Type': 'application/json', ...(fetchOpts.headers ?? {}) }

  let res
  try {
    res = await fetch(BASE + path, {
      ...fetchOpts,
      headers,
      credentials: 'include',
      signal: controller.signal,
    })
  } catch (err) {
    clearTimeout(tid)
    if (err.name === 'AbortError') throw new Error('Request timed out')
    throw err
  }
  clearTimeout(tid)

  if (res.status === 401) {
    if (suppressUnauthorized) {
      throw await responseError(res)
    }
    emitUnauthorized()
    return null
  }

  if (!res.ok) {
    throw await responseError(res)
  }

  // 204 No Content
  if (res.status === 204) return null

  return res.json()
}

export function apiPost(path, body, opts = {}) {
  return apiFetch(path, { ...opts, method: 'POST', body: JSON.stringify(body) })
}

export function apiPatch(path, body, opts = {}) {
  return apiFetch(path, { ...opts, method: 'PATCH', body: JSON.stringify(body) })
}

export function apiDelete(path, body, opts = {}) {
  const fetchOpts = { ...opts, method: 'DELETE' }
  if (body !== undefined) fetchOpts.body = JSON.stringify(body)
  return apiFetch(path, fetchOpts)
}
