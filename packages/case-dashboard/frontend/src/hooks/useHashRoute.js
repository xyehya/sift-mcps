import { useCallback, useEffect } from 'react'

import { useStoreSlice } from '@/store/useStore'
import { DEFAULT_TAB, VALID_TABS } from '@/lib/nav'

// ─────────────────────────────────────────────────────────────────────────
// URL-hash deep-linking (spec §0 + §3, LOCKED). The zustand store
// (`activeTab`) stays the in-memory source of truth; the location hash is the
// REFLECTED state + an ENTRY channel:
//   • store.activeTab changes  → hash rewritten to `#/<tab>` (shareable URL)
//   • hashchange (back/forward, paste-in link) → store.activeTab updated
//   • invalid / empty hash      → default tab (and the URL is normalised)
// We guard against the obvious feedback loop by writing the hash with
// history.replaceState (no extra history entry) and only updating the store
// when the parsed tab actually differs.
// ─────────────────────────────────────────────────────────────────────────

/** Parse `location.hash` → a valid tab id, or null when it doesn't map. */
export function parseHashTab(hash) {
  const raw = (hash || '').replace(/^#\/?/, '').trim().toLowerCase()
  if (raw && VALID_TABS.has(raw)) return raw
  return null
}

export function useHashRoute() {
  const { activeTab, setActiveTab } = useStoreSlice((s) => ({
    activeTab: s.activeTab,
    setActiveTab: s.setActiveTab,
  }))

  // Apply the current hash to the store (entry + back/forward channel).
  const syncFromHash = useCallback(() => {
    const fromHash = parseHashTab(window.location.hash)
    if (fromHash) {
      setActiveTab(fromHash)
    } else {
      // Empty/invalid hash → fall back to the default and normalise the URL.
      setActiveTab(DEFAULT_TAB)
      const target = `#/${DEFAULT_TAB}`
      if (window.location.hash !== target) {
        window.history.replaceState(null, '', target)
      }
    }
  }, [setActiveTab])

  // On mount + on every hashchange (covers browser back/forward and pasted links).
  useEffect(() => {
    syncFromHash()
    window.addEventListener('hashchange', syncFromHash)
    return () => window.removeEventListener('hashchange', syncFromHash)
  }, [syncFromHash])

  // Reflect store → hash. replaceState avoids spamming history when the store
  // is driven programmatically (nav click already pushes a real entry below).
  useEffect(() => {
    const target = `#/${activeTab}`
    if (window.location.hash !== target) {
      window.history.replaceState(null, '', target)
    }
  }, [activeTab])
}

/**
 * navigateToTab — push a real history entry for an intentional navigation
 * (nav click, command palette, KPI click) so the browser Back button returns
 * to the previous tab. The store update flows through the reflect effect.
 */
export function navigateToTab(setActiveTab, tab) {
  if (!VALID_TABS.has(tab)) return
  const target = `#/${tab}`
  if (window.location.hash !== target) {
    window.history.pushState(null, '', target)
  }
  setActiveTab(tab)
}
