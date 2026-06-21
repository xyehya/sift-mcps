import { Suspense, lazy, useCallback, useEffect, useRef, useState } from 'react'

import { useStoreSlice } from '@/store/useStore'
import { useDataPolling } from '@/hooks/useDataPolling'
import { useHashRoute } from '@/hooks/useHashRoute'
import { useHotkey } from '@/hooks/useHotkeys'
import { useToastBridge } from '@/hooks/useToastBridge'
import { tabLabel } from '@/lib/nav'
import { SideNav } from '@/components/layout/SideNav'
import { Header } from '@/components/layout/Header'
import { StatusBar } from '@/components/layout/StatusBar'
import { CommandPalette } from '@/components/layout/CommandPalette'
import { CommitDrawer } from '@/components/layout/CommitDrawer'
import { TabPlaceholder } from '@/components/layout/TabPlaceholder'
import { SkeletonBlock } from '@/components/common/Skeleton'

// ─────────────────────────────────────────────────────────────────────────
// AppShell (spec §3 layout + §4 IA) — the authenticated frame: collapsible
// SideNav (auto-collapse <1024), Header strip, a focusable <main> content
// region, StatusBar, plus the CommandPalette + CommitDrawer hosts. Owns the
// 15s data poll, hash routing, and the ⌘K hotkey.
//
// Tab CONTENT: each tab is React.lazy-loaded behind a <Suspense> boundary so
// the initial bundle stays small (PERF-1); the tabId→component mapping is a
// data-driven registry (MOD-2) rather than an if-ladder. Heavy vendors
// (react/radix/framer-motion/recharts) are split into vendor chunks via the
// Rollup manualChunks config in vite.config.js.
// ─────────────────────────────────────────────────────────────────────────

const MOBILE_BREAKPOINT = 1024

// tabId → lazy component registry (data-driven; MOD-2). Each entry is a
// route-level code-split point (PERF-1). default-export interop: the tab
// modules are named exports, so re-map to `default` for React.lazy.
const TAB_COMPONENTS = {
  overview: lazy(() => import('@/components/overview/OverviewTab').then((m) => ({ default: m.OverviewTab }))),
  findings: lazy(() => import('@/components/findings/FindingsTab').then((m) => ({ default: m.FindingsTab }))),
  evidence: lazy(() => import('@/components/evidence/EvidenceTab').then((m) => ({ default: m.EvidenceTab }))),
  backends: lazy(() => import('@/components/backends/BackendsTab').then((m) => ({ default: m.BackendsTab }))),
  // === ENTITY tabs (Timeline · Hosts · Accounts · IOCs) ===
  timeline: lazy(() => import('@/components/timeline/TimelineTab').then((m) => ({ default: m.TimelineTab }))),
  hosts: lazy(() => import('@/components/hosts/HostsTab').then((m) => ({ default: m.HostsTab }))),
  accounts: lazy(() => import('@/components/accounts/AccountsTab').then((m) => ({ default: m.AccountsTab }))),
  iocs: lazy(() => import('@/components/iocs/IocsTab').then((m) => ({ default: m.IocsTab }))),
  // === REPORT tabs (Reports · TODOs · Settings) ===
  reports: lazy(() => import('@/components/reports/ReportsTab').then((m) => ({ default: m.ReportsTab }))),
  todos: lazy(() => import('@/components/todos/TodosTab').then((m) => ({ default: m.TodosTab }))),
  settings: lazy(() => import('@/components/settings/SettingsTab').then((m) => ({ default: m.SettingsTab }))),
}

/** Token skeleton shown while a lazy tab chunk resolves (Suspense fallback). */
function TabFallback() {
  return (
    <div className="p-6">
      <SkeletonBlock rows={8} gap={12} />
    </div>
  )
}

/** Render the active tab's content from the lazy registry; unknown → placeholder. */
function TabContent({ tabId }) {
  const Tab = TAB_COMPONENTS[tabId]
  if (!Tab) return <TabPlaceholder tabId={tabId} />
  return (
    <Suspense fallback={<TabFallback />}>
      <Tab />
    </Suspense>
  )
}

export function AppShell() {
  useDataPolling()
  useHashRoute()
  useToastBridge()

  const { activeTab, setCommandPaletteOpen } = useStoreSlice((s) => ({
    activeTab: s.activeTab,
    setCommandPaletteOpen: s.setCommandPaletteOpen,
  }))

  // Sidebar collapse: auto-collapse below 1024 (spec §2 responsive), but let
  // the operator override via the toggle. We only force-collapse on crossing
  // the breakpoint downward; manual state is preserved above it.
  const [collapsed, setCollapsed] = useState(
    () => typeof window !== 'undefined' && window.innerWidth < MOBILE_BREAKPOINT,
  )
  useEffect(() => {
    function onResize() {
      if (window.innerWidth < MOBILE_BREAKPOINT) setCollapsed(true)
    }
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  // a11y: move focus to the main region on tab change so keyboard/SR users
  // land on the new content rather than staying on the nav item.
  const mainRef = useRef(null)
  useEffect(() => {
    mainRef.current?.focus()
  }, [activeTab])

  const openPalette = useCallback(() => setCommandPaletteOpen(true), [setCommandPaletteOpen])
  useHotkey({ key: 'k', meta: true, allowInInput: true }, openPalette)

  // Zoom/reflow (WCAG 1.4.10, RUN-4c #26): the shell PARTICIPATES in layout — the
  // sidebar is an in-flow flex column (not fixed), and the whole frame keeps a
  // sensible minimum width (`min-w-[64rem]`). When the viewport is narrower than
  // that (e.g. ~400% browser zoom), the OUTER container scrolls HORIZONTALLY
  // instead of the sidebar overlapping the body content. The inner panes still
  // own their own vertical scroll.
  return (
    <div className="h-screen overflow-x-auto overflow-y-hidden bg-background text-foreground">
      <div className="flex h-full min-w-[64rem]">
        <SideNav collapsed={collapsed} onToggleCollapsed={() => setCollapsed((c) => !c)} />

        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <Header onOpenCommandPalette={openPalette} />

          <main
            ref={mainRef}
            tabIndex={-1}
            aria-label={`${tabLabel(activeTab)} content`}
            className="flex-1 overflow-y-auto outline-none"
          >
            <TabContent tabId={activeTab} />
          </main>

          <StatusBar />
        </div>
      </div>

      {/* Global overlays (portal-rendered) */}
      <CommandPalette />
      <CommitDrawer />
    </div>
  )
}
