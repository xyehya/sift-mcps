import { PanelLeftClose, PanelLeftOpen } from 'lucide-react'

import { cn } from '@/lib/utils'
import { NAV_GROUPS } from '@/lib/nav'
import { navigateToTab } from '@/hooks/useHashRoute'
import { useStoreSlice } from '@/store/useStore'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// SideNav (spec §4) — grouped destinations with labels + Lucide icons, active
// highlight, store-derived badges (pending findings / open todos), and a
// collapsed (icon-only) mode for <1024 widths or operator preference.
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
      {/* Active rail indicator */}
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
      {/* Brand strip */}
      <div className={cn('flex h-14 items-center gap-2 border-b border-border px-4', collapsed && 'justify-center px-0')}>
        <span aria-hidden className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary">
          <ShieldGlyph />
        </span>
        {!collapsed && (
          <span className="truncate text-sm font-semibold tracking-tight text-foreground">SIFT Examiner</span>
        )}
      </div>

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

      {/* Collapse toggle */}
      <div className={cn('border-t border-border p-2', collapsed ? 'flex justify-center' : '')}>
        <Button
          type="button"
          variant="ghost"
          size={collapsed ? 'icon' : 'sm'}
          onClick={onToggleCollapsed}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={cn(!collapsed && 'w-full justify-start gap-2 text-muted-foreground')}
        >
          {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
          {!collapsed && <span>Collapse</span>}
        </Button>
      </div>
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
