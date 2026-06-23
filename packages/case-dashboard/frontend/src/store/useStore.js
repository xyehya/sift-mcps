import { create } from 'zustand'
import { useShallow } from 'zustand/react/shallow'

// ─────────────────────────────────────────────────────────────────────────
// Slice-organized store (spec §3). Each slice is a factory `(set, get) => ({…})`
// merged into ONE flat store. The flat public surface (state keys + action
// names) is a hard contract pinned by src/test/useStore.interface.test.js — do
// NOT add or remove top-level keys here without updating that contract test
// (which requires operator + orchestrator sign-off, per the port guardrail).
// ─────────────────────────────────────────────────────────────────────────

/** Navigation slice — active tab + the two host drawers/overlays. */
const createNavigationSlice = (set) => ({
  activeTab: 'overview',
  setActiveTab: (tab) => set({ activeTab: tab }),

  commitDrawerOpen: false,
  setCommitDrawerOpen: (v) => set({ commitDrawerOpen: v }),

  commandPaletteOpen: false,
  setCommandPaletteOpen: (v) => set({ commandPaletteOpen: v }),
})

/** Auth + active-case identity slice. */
const createSessionSlice = (set) => ({
  user: null,
  setUser: (user) => set({ user }),

  activeCase: null,
  setActiveCase: (c) => set({ activeCase: c }),

  cases: [],
  setCases: (cases) => set({ cases }),
})

/** Findings slice — list, selection, the three filters, and staged delta. */
const createFindingsSlice = (set) => ({
  findings: [],
  setFindings: (findings) => set({ findings }),
  selectedFindingId: null,
  setSelectedFindingId: (id) => set({ selectedFindingId: id }),
  findingsFilter: 'pending',
  setFindingsFilter: (f) => set({ findingsFilter: f }),
  findingsHostFilter: null,
  setFindingsHostFilter: (host) => set({ findingsHostFilter: host }),
  findingsAccountFilter: null,
  setFindingsAccountFilter: (account) => set({ findingsAccountFilter: account }),

  // Delta (staged review changes — approve/reject/edit awaiting commit).
  delta: [],
  setDelta: (delta) => set({ delta }),
})

/** Investigation-data slice — everything the 15s poll refreshes. */
const createInvestigationSlice = (set) => ({
  summary: null,
  setSummary: (summary) => set({ summary }),

  iocs: [],
  setIocs: (iocs) => set({ iocs }),

  todos: [],
  setTodos: (todos) => set({ todos }),

  reports: [],
  setReports: (reports) => set({ reports }),

  timeline: [],
  setTimeline: (timeline) => set({ timeline }),

  agentActivity: [],
  setAgentActivity: (agentActivity) => set({ agentActivity }),

  // Evidence chain seal/custody status.
  chainStatus: null,
  setChainStatus: (chainStatus) => set({ chainStatus }),

  // Portal state (DB authority: evidence seal/custody, add-on status, report eligibility).
  portalState: null,
  setPortalState: (portalState) => set({ portalState }),
})

/** Sync / loading lifecycle slice. */
const createSyncSlice = (set) => ({
  // Loading state (true until the first data fetch resolves).
  isLoading: true,
  setIsLoading: (v) => set({ isLoading: v }),

  lastSync: null,
  setLastSync: (ts) => set({ lastSync: ts }),
})

/** Transient toast slice (auto-dismissing notices). */
const createToastSlice = (set, get) => ({
  toasts: [],
  addToast: (msg, type = 'info') => {
    const id = Date.now()
    set((s) => ({ toasts: [...s.toasts, { id, msg, type }] }))
    setTimeout(() => get().dismissToast(id), 4000)
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
})

export const useStore = create((set, get) => ({
  ...createNavigationSlice(set, get),
  ...createSessionSlice(set, get),
  ...createFindingsSlice(set, get),
  ...createInvestigationSlice(set, get),
  ...createSyncSlice(set, get),
  ...createToastSlice(set, get),
}))

/**
 * useStoreSlice — subscribe to a derived slice with shallow equality so
 * components only re-render when the selected fields actually change.
 */
export function useStoreSlice(selector) {
  return useStore(useShallow(selector))
}
