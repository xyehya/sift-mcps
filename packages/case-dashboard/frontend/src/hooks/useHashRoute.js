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

/** Parse `location.hash` → a valid tab id, or null when it doesn't map. The
   optional `?…` filter query (RUN-4c, see parseHashFilters) is stripped before
   matching, so `#/findings?sev=high` still routes to the `findings` tab. */
export function parseHashTab(hash) {
  const raw = (hash || '').replace(/^#\/?/, '').split('?')[0].trim().toLowerCase()
  if (raw && VALID_TABS.has(raw)) return raw
  return null
}

/** The confidence/severity values the Findings filter query may carry. */
const HASH_SEVERITIES = new Set(['high', 'medium', 'low', 'speculative'])

/**
 * parseHashFilters — extract the orthogonal Findings filter that rides the hash
 * query (`#/findings?sev=high`). The status filter lives in the store; the
 * confidence/severity filter has no store key (the surface is frozen) so it is
 * carried here, where it is shareable. Returns `{ sev }` (UPPERCASE) or `{}`.
 */
export function parseHashFilters(hash) {
  const q = (hash || '').split('?')[1]
  if (!q) return {}
  const sev = new URLSearchParams(q).get('sev')
  if (sev && HASH_SEVERITIES.has(sev.toLowerCase())) return { sev: sev.toUpperCase() }
  return {}
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
  // We compare only the TAB SEGMENT so an attached `?…` filter query (RUN-4c) is
  // preserved while on the same tab, and dropped when the tab actually changes.
  useEffect(() => {
    const current = window.location.hash
    if (parseHashTab(current) === activeTab) return
    const target = `#/${activeTab}`
    if (current !== target) {
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

/**
 * navigateToFindings — deep-link to the Findings tab carrying the confidence/
 * severity filter in the hash query (`#/findings?sev=high`), so the filtered
 * view is shareable. Pass `{ sev }` (any case) or `{}` for an unfiltered jump.
 * The reflect effect preserves this query; FindingsTab reads it via
 * parseHashFilters. Pushes a real history entry (Back returns to the prior tab).
 */
export function navigateToFindings(setActiveTab, { sev } = {}) {
  const s = sev && HASH_SEVERITIES.has(String(sev).toLowerCase()) ? String(sev).toLowerCase() : null
  const target = s ? `#/findings?sev=${s}` : '#/findings'
  if (window.location.hash !== target) {
    window.history.pushState(null, '', target)
  }
  setActiveTab('findings')
}
