import { create } from 'zustand'

export const useStore = create((set, get) => ({
  // Navigation
  activeTab: 'overview',
  setActiveTab: (tab) => set({ activeTab: tab }),

  // Auth
  user: null,
  setUser: (user) => set({ user }),

  // Active case
  activeCase: null,
  setActiveCase: (c) => set({ activeCase: c }),

  // Cases list
  cases: [],
  setCases: (cases) => set({ cases }),

  // Summary (for KPIs)
  summary: null,
  setSummary: (summary) => set({ summary }),

  // Findings
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

  // Delta (staged changes)
  delta: [],
  setDelta: (delta) => set({ delta }),

  // IOCs
  iocs: [],
  setIocs: (iocs) => set({ iocs }),

  // TODOs
  todos: [],
  setTodos: (todos) => set({ todos }),

  // Reports
  reports: [],
  setReports: (reports) => set({ reports }),

  // Timeline
  timeline: [],
  setTimeline: (timeline) => set({ timeline }),

  // Evidence chain
  chainStatus: null,
  setChainStatus: (chainStatus) => set({ chainStatus }),

  // Portal state (DB authority: evidence seal/custody, add-on status, report eligibility)
  portalState: null,
  setPortalState: (portalState) => set({ portalState }),

  // Loading state (true until first data fetch resolves)
  isLoading: true,
  setIsLoading: (v) => set({ isLoading: v }),

  // Last sync timestamp
  lastSync: null,
  setLastSync: (ts) => set({ lastSync: ts }),

  // Toasts
  toasts: [],
  addToast: (msg, type = 'info') => {
    const id = Date.now()
    set((s) => ({ toasts: [...s.toasts, { id, msg, type }] }))
    setTimeout(() => get().dismissToast(id), 4000)
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  // Commit drawer open state
  commitDrawerOpen: false,
  setCommitDrawerOpen: (v) => set({ commitDrawerOpen: v }),

  // Command palette open state
  commandPaletteOpen: false,
  setCommandPaletteOpen: (v) => set({ commandPaletteOpen: v }),
}))