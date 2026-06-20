import {
  LayoutGrid,
  ListChecks,
  Clock,
  ShieldCheck,
  MonitorSmartphone,
  Users,
  Crosshair,
  FileText,
  CheckSquare,
  Server,
  Settings,
} from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────
// Navigation model (spec §4 / DESIGN-SYSTEM.md). All 11 destinations, grouped
// as the round-2 Mission-Control IA: COMMAND / INVESTIGATION / OPERATIONS.
// `badge` names a store-derived count surfaced on the nav item. This registry
// is the single source for SideNav + the hash router (valid tab ids) + the
// command palette.
// ─────────────────────────────────────────────────────────────────────────

export const NAV_GROUPS = [
  {
    label: 'Command',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutGrid, badge: 'blockedActions' },
    ],
  },
  {
    label: 'Investigation',
    items: [
      { id: 'findings', label: 'Findings', icon: ListChecks, badge: 'pendingFindings' },
      { id: 'timeline', label: 'Timeline', icon: Clock },
      { id: 'evidence', label: 'Evidence', icon: ShieldCheck },
      { id: 'hosts', label: 'Hosts', icon: MonitorSmartphone },
      { id: 'accounts', label: 'Accounts', icon: Users },
    ],
  },
  {
    label: 'Operations',
    items: [
      { id: 'iocs', label: 'IOCs', icon: Crosshair },
      { id: 'todos', label: 'TODOs', icon: CheckSquare, badge: 'openTodos' },
      { id: 'backends', label: 'Backends', icon: Server },
      { id: 'reports', label: 'Reports', icon: FileText },
      { id: 'settings', label: 'Settings', icon: Settings },
    ],
  },
]

/** Flat list of every nav item, in display order. */
export const NAV_ITEMS = NAV_GROUPS.flatMap((g) => g.items)

/** Set of valid tab ids — used to validate inbound URL hashes. */
export const VALID_TABS = new Set(NAV_ITEMS.map((i) => i.id))

export const DEFAULT_TAB = 'overview'

/** Human label for a tab id (falls back to the id). */
export function tabLabel(id) {
  return NAV_ITEMS.find((i) => i.id === id)?.label ?? id
}
