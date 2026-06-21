// ─────────────────────────────────────────────────────────────────────────
// DEV-ONLY mock route table. apiFetch() consults this (behind
// `window.__SIFT_MOCK__`) so tabs whose data comes from a live GET — rather
// than the seeded zustand store — still render POPULATED in ?mock=1 with no
// gateway. This is the API-ADAPTER-layer mock/real split (AGENTS §3): NO
// component handler ever branches on isMock; the split lives here, consumed
// once inside apiFetch.
//
// Loaded ONLY via dynamic import() from apiFetch and gated by
// `import.meta.env.DEV && window.__SIFT_MOCK__`, so the production bundle
// tree-shakes this module (and the fixtures it pulls) out entirely.
//
// Returns a sentinel { __mockHandled: false } when a path/method is not mocked
// so apiFetch falls through to the real fetch unchanged.
// ─────────────────────────────────────────────────────────────────────────

const NOT_HANDLED = { __mockHandled: false }

/**
 * Resolve a mock response for (path, method). GETs return read fixtures;
 * mutating verbs resolve to a benign restart-required stub so the toast/refresh
 * paths exercise without a backend. Anything else → NOT_HANDLED.
 *
 * @param {string} path   request path WITHOUT the /portal base (e.g. /api/backends)
 * @param {string} method upper-case HTTP method
 */
export async function mockRoute(path, method) {
  const { BACKENDS_REGISTRY, HEALTH_PAYLOAD } = await import('@/_mock/fixtures')

  // ── Reads ──────────────────────────────────────────────────────────────
  if (method === 'GET') {
    if (path === '/api/backends') return { backends: BACKENDS_REGISTRY }
    if (path === '/api/health') return HEALTH_PAYLOAD
    return NOT_HANDLED
  }

  // ── Mutations (challenge-gated admin actions) ────────────────────────────
  // No real registry to mutate in mock; resolve to a benign restart-required
  // stub so the success-toast + refresh path renders. The subsequent
  // GET /api/backends just re-serves the static fixture.
  const mutates =
    path === '/api/backends' || // register
    path === '/api/backends/reload' ||
    path === '/api/backends/validate' ||
    /^\/api\/backends\/[^/]+$/.test(path) || // unregister (DELETE)
    /^\/api\/backends\/[^/]+\/enabled$/.test(path) ||
    /^\/api\/services\/[^/]+\/(start|stop|restart)$/.test(path)

  if (mutates && (method === 'POST' || method === 'DELETE')) {
    if (path === '/api/backends/validate') {
      return {
        valid: true,
        namespace: 'mock-backend',
        provides: ['demo:capability'],
        requires: [],
        unmet_requires: [],
        tools: [{ name: 'demo.tool', description: 'Mock validation result (no gateway).' }],
        instructions: 'Demo manifest validated against the mock adapter.',
      }
    }
    return { restart_required: true, status: 'pending' }
  }

  return NOT_HANDLED
}

export { NOT_HANDLED }
