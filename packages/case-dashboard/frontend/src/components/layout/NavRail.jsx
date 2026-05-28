import { useStore } from '../../store/useStore'
import clsx from 'clsx'

const NAV_ITEMS = [
  { id: 'overview',  label: 'Overview',  icon: IconGrid },
  { id: 'findings',  label: 'Findings',  icon: IconList,  badge: 'pendingCount' },
  { id: 'timeline',  label: 'Timeline',  icon: IconClock },
  { id: 'evidence',  label: 'Evidence',  icon: IconShield },
  { id: 'hosts',     label: 'Hosts',     icon: IconHost },
  { id: 'accounts',  label: 'Accounts',  icon: IconUser },
  { id: 'iocs',      label: 'IOCs',      icon: IconTarget },
  { id: 'todos',     label: 'TODOs',     icon: IconCheck,  badge: 'todoCount' },
  { id: 'reports',   label: 'Reports',   icon: IconFile },
]

const BOTTOM_ITEMS = [
  { id: 'settings', label: 'Settings', icon: IconGear },
]

export function NavRail() {
  const { activeTab, setActiveTab, findings, delta, summary } = useStore()
  const pendingCount = findings.filter((f) => f.status === 'draft').length
  const stagedCount = delta.length
  const todoOpenCount = summary?.todos?.open ?? 0

  function getBadge(key) {
    if (key === 'pendingCount') return pendingCount > 0 ? pendingCount : null
    if (key === 'todoCount') return todoOpenCount > 0 ? todoOpenCount : null
    return null
  }

  return (
    <nav className="flex flex-col items-center w-12 shrink-0 bg-bg-surface border-r border-border-faint py-3 z-20">
      <div className="flex flex-col gap-1 flex-1">
        {NAV_ITEMS.map(({ id, label, icon: Icon, badge }) => {
          const count = badge ? getBadge(badge) : null
          return (
            <NavButton
              key={id}
              active={activeTab === id}
              onClick={() => setActiveTab(id)}
              label={label}
              count={count}
            >
              <Icon />
            </NavButton>
          )
        })}
      </div>
      <div className="flex flex-col gap-1 mt-auto border-t border-border-faint pt-2">
        {BOTTOM_ITEMS.map(({ id, label, icon: Icon }) => (
          <NavButton
            key={id}
            active={activeTab === id}
            onClick={() => setActiveTab(id)}
            label={label}
          >
            <Icon />
          </NavButton>
        ))}
      </div>
    </nav>
  )
}

function NavButton({ active, onClick, label, count, children }) {
  return (
    <button
      onClick={onClick}
      title={label}
      className={clsx(
        'relative w-9 h-9 rounded flex items-center justify-center transition-colors duration-100 group',
        active
          ? 'bg-cyan-dim text-cyan'
          : 'text-text-muted hover:text-text-primary hover:bg-bg-raised'
      )}
      style={active ? { backgroundColor: 'var(--cyan-dim)', color: 'var(--cyan)' } : {}}
    >
      <span className="w-5 h-5">{children}</span>
      {count != null && (
        <span className="absolute top-0.5 right-0.5 min-w-[14px] h-[14px] px-[3px] rounded-full bg-crimson text-white font-mono text-[9px] flex items-center justify-center leading-none"
          style={{ backgroundColor: 'var(--crimson)', color: '#fff' }}>
          {count > 99 ? '99+' : count}
        </span>
      )}
      {/* Tooltip */}
      <span className="pointer-events-none absolute left-11 px-2 py-1 rounded text-xs font-sans whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity z-50"
        style={{ background: 'var(--bg-overlay)', color: 'var(--text-primary)', border: '1px solid var(--border-soft)' }}>
        {label}
      </span>
    </button>
  )
}

// SVG icons — minimal outlines
function IconGrid() {
  return <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="2" width="7" height="7" rx="1"/><rect x="11" y="2" width="7" height="7" rx="1"/><rect x="2" y="11" width="7" height="7" rx="1"/><rect x="11" y="11" width="7" height="7" rx="1"/></svg>
}
function IconList() {
  return <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><line x1="3" y1="5" x2="17" y2="5"/><line x1="3" y1="10" x2="17" y2="10"/><line x1="3" y1="15" x2="17" y2="15"/></svg>
}
function IconClock() {
  return <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="10" cy="10" r="8"/><line x1="10" y1="5" x2="10" y2="10"/><line x1="10" y1="10" x2="14" y2="13"/></svg>
}
function IconShield() {
  return <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10 2L3 5v6c0 4 3.5 6.5 7 8 3.5-1.5 7-4 7-8V5L10 2z"/></svg>
}
function IconTarget() {
  return <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="10" cy="10" r="8"/><circle cx="10" cy="10" r="4"/><circle cx="10" cy="10" r="1" fill="currentColor"/></svg>
}
function IconCheck() {
  return <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="4" width="14" height="14" rx="1"/><line x1="7" y1="9" x2="9" y2="11"/><line x1="9" y1="11" x2="13" y2="7"/></svg>
}
function IconGear() {
  return <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="10" cy="10" r="3"/><path d="M10 2v2M10 16v2M2 10h2M16 10h2M4.2 4.2l1.4 1.4M14.4 14.4l1.4 1.4M4.2 15.8l1.4-1.4M14.4 5.6l1.4-1.4"/></svg>
}

function IconFile() {
  return <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M5 2h7l4 4v12a1 1 0 01-1 1H5a1 1 0 01-1-1V3a1 1 0 011-1z"/><path d="M12 2v4h4"/></svg>
}

function IconHost() {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="3" y="3" width="14" height="10" rx="1.5" />
      <line x1="6" y1="16" x2="14" y2="16" />
      <line x1="10" y1="13" x2="10" y2="16" />
    </svg>
  )
}

function IconUser() {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="10" cy="7" r="3.5" />
      <path d="M4 17c0-3.3 2.7-6 6-6s6 2.7 6 6" />
    </svg>
  )
}

