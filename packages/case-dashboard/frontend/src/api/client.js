const BASE = '/portal'
const TIMEOUT_MS = 15000
// Evidence hashing operations (seal / proof-export / verify / delete) re-hash the
// mounted bytes synchronously and can take minutes for large disk/memory images,
// so they opt into a much longer client timeout via opts.timeoutMs.
export const LONG_TIMEOUT_MS = 900000 // 15 min

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
  const { suppressUnauthorized = false, timeoutMs = TIMEOUT_MS, ...fetchOpts } = opts

  // DEV-ONLY mock/real split (AGENTS §3): when fixtures are installed (?mock=1),
  // consult the mock route table BEFORE the network. Handled paths return a
  // fixture; unhandled paths fall through to the real fetch below. Gated by
  // import.meta.env.DEV so the dynamic import (and the fixtures) tree-shake out
  // of production builds.
  if (
    import.meta.env.DEV &&
    typeof window !== 'undefined' &&
    window.__SIFT_MOCK__
  ) {
    const { mockRoute } = await import('@/_mock/routes')
    const result = await mockRoute(path, (fetchOpts.method || 'GET').toUpperCase())
    if (!result || result.__mockHandled !== false) {
      return result
    }
  }

  const tid = setTimeout(() => controller.abort(), timeoutMs)

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
    if (err.name === 'AbortError') throw new Error('Request timed out', { cause: err })
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
