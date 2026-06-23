import { useCallback } from 'react'
import { useStoreSlice } from '../store/useStore'
import { getDelta } from '../api/endpoints'

// Eager refetch of /api/delta (B2). The 15s background poll in useDataPolling
// is the steady-state sync, but the autonomous agent mutates staged deltas
// server-side between polls, so the Commit badge + drawer can lag reality. Call
// this on commit-drawer open and immediately after every stage/approve/reject/
// commit action to reflect server truth without waiting for the next tick.
//
// Reuses the same adapter path as the poll (getDelta + items ?? []) and honours
// the same DEV mock-skip guard so it never clobbers seeded ?mock fixtures.
export function useDeltaRefetch() {
  const setDelta = useStoreSlice((s) => s.setDelta)

  return useCallback(async () => {
    if (typeof window !== 'undefined' && window.__SIFT_MOCK__) return
    try {
      const res = await getDelta()
      if (res) setDelta(res.items ?? [])
    } catch {
      // Non-fatal: the 15s poll remains the backstop. Mutations that triggered
      // this refetch already updated the store optimistically.
    }
  }, [setDelta])
}
