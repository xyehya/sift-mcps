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

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
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

      {/* Global overlays */}
      <CommandPalette />
      <CommitDrawer />
    </div>
  )
}
