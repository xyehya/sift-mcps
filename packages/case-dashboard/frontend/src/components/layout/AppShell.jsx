import { useCallback, useEffect, useRef, useState } from 'react'

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
import { OverviewTab } from '@/components/overview/OverviewTab'
import { FindingsTab } from '@/components/findings/FindingsTab'
import { EvidenceTab } from '@/components/evidence/EvidenceTab'
import { BackendsTab } from '@/components/backends/BackendsTab'
// === ENTITY tabs (Timeline · Hosts · Accounts · IOCs) ===
import { TimelineTab } from '@/components/timeline/TimelineTab'
import { HostsTab } from '@/components/hosts/HostsTab'
import { AccountsTab } from '@/components/accounts/AccountsTab'
import { IocsTab } from '@/components/iocs/IocsTab'
// === REPORT tabs (Reports · TODOs · Settings) ===
import { ReportsTab } from '@/components/reports/ReportsTab'
import { TodosTab } from '@/components/todos/TodosTab'
import { SettingsTab } from '@/components/settings/SettingsTab'

// ─────────────────────────────────────────────────────────────────────────
// AppShell (spec §3 layout + §4 IA) — the authenticated frame: collapsible
// SideNav (auto-collapse <1024), Header strip, a focusable <main> content
// region, StatusBar, plus the CommandPalette + CommitDrawer hosts. Owns the
// 15s data poll, hash routing, and the ⌘K hotkey.
//
// Tab CONTENT: Overview + Findings are the RUN-3 reference tabs (wired below);
// the remaining tabs render the on-brand TabPlaceholder until their Phase-1
// feature agents build them.
// ─────────────────────────────────────────────────────────────────────────

const MOBILE_BREAKPOINT = 1024

/** Render the active tab's content (reference tabs built; rest = placeholder). */
function TabContent({ tabId }) {
  if (tabId === 'overview') return <OverviewTab />
  if (tabId === 'findings') return <FindingsTab />
  if (tabId === 'evidence') return <EvidenceTab />
  if (tabId === 'backends') return <BackendsTab />
  // === ENTITY tabs (Timeline · Hosts · Accounts · IOCs) ===
  if (tabId === 'timeline') return <TimelineTab />
  if (tabId === 'hosts') return <HostsTab />
  if (tabId === 'accounts') return <AccountsTab />
  if (tabId === 'iocs') return <IocsTab />
  // === REPORT tabs (Reports · TODOs · Settings) ===
  if (tabId === 'reports') return <ReportsTab />
  if (tabId === 'todos') return <TodosTab />
  if (tabId === 'settings') return <SettingsTab />
  return <TabPlaceholder tabId={tabId} />
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

        <div className="flex min-w-0 flex-1 flex-col">
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
