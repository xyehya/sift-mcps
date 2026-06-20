import { motion } from 'framer-motion'
import { ChevronsLeft, ChevronsRight, LogOut } from 'lucide-react'

import { cn } from '@/lib/utils'
import { NAV_GROUPS } from '@/lib/nav'
import { navigateToTab } from '@/hooks/useHashRoute'
import { useStoreSlice } from '@/store/useStore'
import { useAuth } from '@/lib/auth-context'
import { deriveAgentState } from '@/lib/agent-state'
import { useMotionVariants } from '@/lib/motion'
import { ThemeToggle } from '@/lib/theme'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// SideNav (spec §4 / DESIGN-SYSTEM.md) — the Mission-Control left rail:
// brand → agent-state panel → grouped destinations (COMMAND / INVESTIGATION /
// OPERATIONS, all 11 ids) → operator footer. Active = orange; Lucide icons;
// store-derived badges (pending findings / open todos). Collapses to icon-only
// below 1024px (or via the brand-strip toggle). Tokens-only; no raw hex.
// Agent panel + footer are presentational re-skins of round-2 — live agent
// authorization wiring lands in RUN-4b.
// ─────────────────────────────────────────────────────────────────────────

/** Resolve the badge count for a nav item from polled store state. */
function useBadgeCounts() {
  return useStoreSlice((s) => ({
    pendingFindings: s.findings.filter((f) => f.status === 'draft').length,
    openTodos: s.summary?.todos?.open ?? 0,
  }))
}

function NavItem({ item, active, collapsed, onSelect, badgeCount }) {
  const Icon = item.icon
  const showBadge = badgeCount > 0
  const button = (
    <button
      type="button"
      onClick={() => onSelect(item.id)}
      aria-current={active ? 'page' : undefined}
      className={cn(
        'group relative flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-0',
        collapsed && 'justify-center px-0',
        active
          ? 'bg-primary/15 text-primary'
          : 'text-muted-foreground hover:bg-secondary hover:text-foreground',
      )}
    >
      {/* Active rail indicator (orange) */}
      {active && (
        <span aria-hidden className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-r-full bg-primary" />
      )}
      <Icon className="size-4 shrink-0" aria-hidden />
      {!collapsed && <span className="flex-1 truncate text-left">{item.label}</span>}
      {showBadge && (
        <span
          className={cn(
            'tnum flex h-5 min-w-5 items-center justify-center rounded-full px-1.5 text-[11px] font-semibold leading-none',
            'bg-primary text-primary-foreground',
            collapsed && 'absolute right-1 top-1 h-4 min-w-4 px-1 text-[9px]',
          )}
        >
          {badgeCount > 99 ? '99+' : badgeCount}
        </span>
      )}
    </button>
  )

  // In collapsed mode the label is hidden, so surface it (and any count) via tooltip.
  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{button}</TooltipTrigger>
        <TooltipContent side="right">
          {item.label}
          {showBadge ? ` · ${badgeCount}` : ''}
        </TooltipContent>
      </Tooltip>
    )
  }
  return button
}

/** Agent-state panel — CLAUDE · AGENT identity + current state + queued count.
   Derived through the shared deriveAgentState() so the sidebar, the Mission-
   Control hero and the StatusBar all agree on the agent's state and the number
   of gated actions awaiting authorization (portalState.gated_actions, falling
   back to staged delta). */
function AgentPanel({ collapsed }) {
  const variants = useMotionVariants()
  const { portalState, delta, chainStatus } = useStoreSlice((s) => ({
    portalState: s.portalState,
    delta: s.delta,
    chainStatus: s.chainStatus,
  }))
  const agent = deriveAgentState(portalState, chainStatus, delta)
  const state = agent.label
  const queued = agent.queued

  const dot = (
    <motion.span
      aria-hidden
      variants={variants.statusDotPulse}
      animate="animate"
      className={cn('size-2 shrink-0 rounded-full', agent.dot)}
    />
  )

  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="flex justify-center py-2" aria-label={`Agent: ${state}`}>
            {dot}
          </div>
        </TooltipTrigger>
        <TooltipContent side="right">
          Claude agent · {state}
          {queued > 0 ? ` · ${queued} gated` : ''}
        </TooltipContent>
      </Tooltip>
    )
  }

  return (
    <div className="mx-3 mt-3 rounded-lg border border-border bg-primary/[0.06] p-3">
      <p className="mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">Claude · Agent</p>
      <div className="mt-1.5 flex items-center gap-2">
        {dot}
        <span className="truncate text-sm font-medium text-foreground">{state}</span>
      </div>
      <p className="mono mt-1 text-[11px] text-muted-foreground">
        {queued > 0 ? `${queued} gated ${queued === 1 ? 'action' : 'actions'} queued` : 'No actions queued'}
      </p>
    </div>
  )
}

/** Operator footer — identity + capability + theme toggle + sign-out. */
function UserFooter({ collapsed }) {
  const { user, logout } = useAuth()
  const name = user?.examiner || user?.email || 'Examiner'
  const role = (user?.role || '').toLowerCase()
  const isExaminer = role === 'examiner'
  const capability = isExaminer ? 'CAN ACT' : 'VIEW ONLY'
  const initials = name
    .split(/[\s.@_-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase())
    .join('')

  const avatar = (
    <span
      aria-hidden
      className="mono flex size-8 shrink-0 items-center justify-center rounded-md bg-secondary text-xs font-semibold text-foreground"
    >
      {initials || 'EX'}
    </span>
  )

  if (collapsed) {
    return (
      <div className="flex flex-col items-center gap-2 border-t border-border p-2">
        {avatar}
        <ThemeToggle />
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 border-t border-border p-3">
      {avatar}
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium text-foreground">{name}</p>
        <p className="mono text-[10px] uppercase tracking-wider text-muted-foreground">
          {role || 'examiner'} · <span className={cn(isExaminer ? 'text-status-approved' : 'text-muted-foreground')}>{capability}</span>
        </p>
      </div>
      <ThemeToggle />
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="ghost" size="icon" onClick={logout} aria-label="Sign out">
            <LogOut className="size-4" />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Sign out</TooltipContent>
      </Tooltip>
    </div>
  )
}

export function SideNav({ collapsed, onToggleCollapsed }) {
  const { activeTab, setActiveTab } = useStoreSlice((s) => ({
    activeTab: s.activeTab,
    setActiveTab: s.setActiveTab,
  }))
  const counts = useBadgeCounts()

  function handleSelect(id) {
    navigateToTab(setActiveTab, id)
  }

  return (
    <nav
      aria-label="Primary"
      className={cn(
        'flex h-full shrink-0 flex-col border-r border-border bg-card transition-[width] duration-200',
        collapsed ? 'w-16' : 'w-60',
      )}
    >
      {/* Brand strip — "Protocol SIFT Gateway" is the portal's hero identity, so
          it is sized up, bright, and allowed to wrap to two lines rather than
          truncate. The collapse control is top-aligned so a two-line brand is
          never squeezed. */}
      <div
        className={cn(
          'flex items-start gap-2.5 border-b border-border px-3 py-3',
          collapsed && 'h-14 items-center justify-center px-0 py-0',
        )}
      >
        <span aria-hidden className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
          <ShieldGlyph />
        </span>
        {!collapsed && (
          <div className="min-w-0 flex-1 leading-tight">
            <p className="font-display text-[15px] font-bold leading-snug tracking-tight text-foreground">
              Protocol SIFT Gateway
            </p>
            <p className="mono mt-0.5 text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Operations Portal</p>
          </div>
        )}
        {!collapsed && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={onToggleCollapsed}
            aria-label="Collapse sidebar"
            className="mt-0.5 size-7 shrink-0"
          >
            <ChevronsLeft className="size-4" />
          </Button>
        )}
      </div>

      <AgentPanel collapsed={collapsed} />

      <ScrollArea className="flex-1">
        <div className="flex flex-col gap-4 px-3 py-4">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="flex flex-col gap-1">
              {!collapsed && (
                <p className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {group.label}
                </p>
              )}
              {group.items.map((item) => (
                <NavItem
                  key={item.id}
                  item={item}
                  active={activeTab === item.id}
                  collapsed={collapsed}
                  onSelect={handleSelect}
                  badgeCount={item.badge ? counts[item.badge] : 0}
                />
              ))}
            </div>
          ))}
        </div>
      </ScrollArea>

      {/* Expand control (only when collapsed — the collapse control lives in the brand strip) */}
      {collapsed && (
        <div className="flex justify-center border-t border-border p-2">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={onToggleCollapsed}
            aria-label="Expand sidebar"
          >
            <ChevronsRight className="size-4" />
          </Button>
        </div>
      )}

      <UserFooter collapsed={collapsed} />
    </nav>
  )
}

/** Minimal shield mark for the brand badge (decorative). */
function ShieldGlyph() {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" className="size-4" aria-hidden>
      <path d="M10 2.5 4 5v5c0 3.6 2.8 5.9 6 7 3.2-1.1 6-3.4 6-7V5l-6-2.5Z" />
      <path d="m7.5 10 1.8 1.8L13 8" />
    </svg>
  )
}
