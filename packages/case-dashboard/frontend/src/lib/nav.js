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
// Navigation model (spec §4). All 11 destinations, grouped (Investigate /
// Evidence / Entities / Manage). `badge` names a store-derived count surfaced
// on the nav item. This registry is the single source for SideNav + the hash
// router (valid tab ids) + the command palette.
// ─────────────────────────────────────────────────────────────────────────

export const NAV_GROUPS = [
  {
    label: 'Investigate',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutGrid },
      { id: 'findings', label: 'Findings', icon: ListChecks, badge: 'pendingFindings' },
      { id: 'timeline', label: 'Timeline', icon: Clock },
    ],
  },
  {
    label: 'Evidence',
    items: [
      { id: 'evidence', label: 'Evidence', icon: ShieldCheck },
      { id: 'backends', label: 'Backends', icon: Server },
    ],
  },
  {
    label: 'Entities',
    items: [
      { id: 'hosts', label: 'Hosts', icon: MonitorSmartphone },
      { id: 'accounts', label: 'Accounts', icon: Users },
      { id: 'iocs', label: 'IOCs', icon: Crosshair },
    ],
  },
  {
    label: 'Manage',
    items: [
      { id: 'reports', label: 'Reports', icon: FileText },
      { id: 'todos', label: 'TODOs', icon: CheckSquare, badge: 'openTodos' },
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
