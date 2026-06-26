import { useStore } from '@/store/useStore'

// ─────────────────────────────────────────────────────────────────────────
// DEV-ONLY mock bootstrap. Seeds the zustand store with demo fixtures and sets
// a runtime flag so the data poll won't clobber them. Imported ONLY behind
// `import.meta.env.DEV && ?mock` via dynamic import() in main.jsx → excluded
// from production bundles. Never referenced in tests.
// ─────────────────────────────────────────────────────────────────────────

export async function installMockData() {
  const { mockState } = await import('@/_mock/fixtures')
  // Mark first so any in-flight poll callback bails before overwriting.
  if (typeof window !== 'undefined') window.__SIFT_MOCK__ = true
  useStore.setState(mockState)
  return mockState.user
}
