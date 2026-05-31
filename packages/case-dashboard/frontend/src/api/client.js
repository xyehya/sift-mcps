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

export async function apiFetch(path, opts = {}) {
  const controller = new AbortController()
  const tid = setTimeout(() => controller.abort(), TIMEOUT_MS)

  const headers = { 'Content-Type': 'application/json', ...(opts.headers ?? {}) }

  let res
  try {
    res = await fetch(BASE + path, {
      ...opts,
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
    emitUnauthorized()
    return null
  }

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(text || `HTTP ${res.status}`)
  }

  // 204 No Content
  if (res.status === 204) return null

  return res.json()
}

export function apiPost(path, body) {
  return apiFetch(path, { method: 'POST', body: JSON.stringify(body) })
}

export function apiPatch(path, body) {
  return apiFetch(path, { method: 'PATCH', body: JSON.stringify(body) })
}

export function apiDelete(path) {
  return apiFetch(path, { method: 'DELETE' })
}
