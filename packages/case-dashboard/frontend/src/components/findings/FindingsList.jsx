import { useEffect, useMemo, useRef, useState } from 'react'
import { Check, ChevronDown, Funnel, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { confClass, normStatus } from '@/components/findings/findings-utils'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'

// ─────────────────────────────────────────────────────────────────────────
// Findings list (handoff §"Left pane") — unified filter-dropdown (replaces
// old tab-strip) + scrollable rows with severity accent bar, ATT&CK chip,
// dual letter badges (sev + status). Receives the already-filtered `list`
// from FindingsTab (which also drives keyboard nav over the same list).
// ─────────────────────────────────────────────────────────────────────────

// ── Segmented control (filter panel groups) ────────────────────────────

function Segmented({ label, options, value, onChange }) {
  return (
    <div>
      <div className="mono mb-2 text-[9px] uppercase tracking-[.12em]" style={{ color: 'var(--text-ghost)' }}>
        {label}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {options.map((opt) => {
          const active = value === opt.value
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => onChange(opt.value)}
              className="mono rounded-[6px] border px-2.5 py-1 text-[11px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              style={{
                background: active ? 'color-mix(in srgb,var(--orange) 12%,transparent)' : 'transparent',
                borderColor: active ? 'color-mix(in srgb,var(--orange) 38%,transparent)' : 'var(--border-soft)',
                color: active ? 'var(--orange)' : 'var(--text-muted)',
              }}
            >
              {opt.label}
            </button>
          )
        })}
      </div>
    </div>
  )
}

// ── Filter dropdown ────────────────────────────────────────────────────

const SEV_OPTIONS = [
  { value: 'ALL', label: 'All' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
]

const STATE_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'pending', label: 'Pending' },
  { value: 'approved', label: 'Approved' },
  { value: 'staged', label: 'Staged' },
  { value: 'rejected', label: 'Rejected' },
]

const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest' },
  { value: 'oldest', label: 'Oldest' },
]

function FilterPanel({ open, onClose, sevFilter, onSevFilter, stateFilter, onStateFilter, sortFilter, onSortFilter, activeCount, onClearAll }) {
  const panelRef = useRef(null)

  // Close on outside click
  useEffect(() => {
    if (!open) return
    function handleClick(e) {
      if (panelRef.current && !panelRef.current.contains(e.target)) onClose()
    }
    function handleKey(e) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('mousedown', handleClick)
    document.addEventListener('keydown', handleKey)
    return () => {
      document.removeEventListener('mousedown', handleClick)
      document.removeEventListener('keydown', handleKey)
    }
  }, [open, onClose])

  if (!open) return null

  return (
    // Lightly translucent panel with dropin animation
    <div
      ref={panelRef}
      className="absolute left-2 right-2 top-full z-20 mt-1 rounded-[10px] border p-4 shadow-lg"
      style={{
        background: 'color-mix(in srgb,var(--bg-overlay) 82%,transparent)',
        backdropFilter: 'blur(16px) saturate(1.4)',
        borderColor: 'var(--border-soft)',
        animation: 'dropin .22s var(--ease-snap) both',
      }}
    >
      <div className="flex flex-col gap-4">
        <Segmented label="Severity" options={SEV_OPTIONS} value={sevFilter} onChange={onSevFilter} />
        <Segmented label="State" options={STATE_OPTIONS} value={stateFilter} onChange={onStateFilter} />
        <Segmented label="Time" options={SORT_OPTIONS} value={sortFilter} onChange={onSortFilter} />
        {activeCount > 0 && (
          <button
            type="button"
            onClick={onClearAll}
            className="mono self-start text-[11px] font-semibold underline"
            style={{ color: 'var(--text-muted)' }}
          >
            Clear all
          </button>
        )}
      </div>
    </div>
  )
}

// ── Filter bar ─────────────────────────────────────────────────────────

function FilterBar({ shown, sevFilter, onSevFilter, stateFilter, onStateFilter, sortFilter, onSortFilter, activeCount, onClearAll }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="relative border-b px-3 py-2" style={{ borderColor: 'var(--border-soft)' }}>
      <div className="flex items-center gap-2">
        <span className="mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
          {shown} shown
        </span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="mono flex items-center gap-1.5 rounded-[7px] border px-2.5 py-1 text-[11px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          style={{
            background: open || activeCount > 0 ? 'color-mix(in srgb,var(--orange) 10%,transparent)' : 'transparent',
            borderColor: open || activeCount > 0 ? 'color-mix(in srgb,var(--orange) 30%,transparent)' : 'var(--border-soft)',
            color: open || activeCount > 0 ? 'var(--orange)' : 'var(--text-muted)',
          }}
        >
          {/* funnel icon */}
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
            <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>
          </svg>
          Filter
          {activeCount > 0 && (
            <span
              className="mono flex size-4 items-center justify-center rounded-full text-[9px] font-bold"
              style={{ background: 'var(--orange)', color: 'var(--on-accent)' }}
            >
              {activeCount}
            </span>
          )}
          <ChevronDown
            className="size-3 transition-transform"
            style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
            aria-hidden
          />
        </button>
      </div>

      <FilterPanel
        open={open}
        onClose={() => setOpen(false)}
        sevFilter={sevFilter}
        onSevFilter={onSevFilter}
        stateFilter={stateFilter}
        onStateFilter={onStateFilter}
        sortFilter={sortFilter}
        onSortFilter={onSortFilter}
        activeCount={activeCount}
        onClearAll={onClearAll}
      />
    </div>
  )
}

// ── Status/severity letter badges ──────────────────────────────────────

// P0 model-shift: SPECULATIVE tier removed; only High / Medium / Low are valid.
const SEV_BADGE = {
  HIGH:   { letter: 'H', color: 'var(--crimson)', label: 'High' },
  MEDIUM: { letter: 'M', color: 'var(--amber)',   label: 'Medium' },
  LOW:    { letter: 'L', color: 'var(--steel)',   label: 'Low' },
}

const ST_BADGE = {
  draft:    { letter: 'P', color: 'var(--amber)',  bg: 'color-mix(in srgb,var(--amber) 18%,transparent)',  label: 'Pending' },
  pending:  { letter: 'P', color: 'var(--amber)',  bg: 'color-mix(in srgb,var(--amber) 18%,transparent)',  label: 'Pending' },
  approved: { letter: 'A', color: 'var(--jade)',   bg: 'color-mix(in srgb,var(--jade) 14%,transparent)',   label: 'Approved' },
  staged:   { letter: 'S', color: 'var(--violet)', bg: 'color-mix(in srgb,var(--violet) 14%,transparent)', label: 'Staged' },
  rejected: { letter: 'R', color: 'var(--crimson)',bg: 'color-mix(in srgb,var(--crimson) 14%,transparent)',label: 'Rejected' },
}

function LetterBadge({ color, bg, letter, title }) {
  return (
    <span
      title={title}
      className="mono inline-grid shrink-0 place-items-center text-[10px] font-bold leading-none"
      style={{
        width: '22px',
        height: '22px',
        borderRadius: '6px',
        color,
        background: bg ?? 'color-mix(in srgb,currentColor 14%,transparent)',
        border: `1px solid color-mix(in srgb,${color} 28%,transparent)`,
      }}
    >
      {letter}
    </span>
  )
}

// ── Row ────────────────────────────────────────────────────────────────

function Row({ finding, active, selected, selectMode, staged, onClick }) {
  const conf = confClass(finding.confidence)
  const sev = (finding.confidence ?? finding.severity ?? '').toUpperCase()
  const sevMeta = SEV_BADGE[sev] ?? { letter: '?', color: 'var(--text-muted)', label: sev }

  const rawStatus = normStatus(finding)
  // If there's a staged delta, reflect that status
  const displayStatus = staged ? staged.action : rawStatus
  const stMeta = ST_BADGE[displayStatus] ?? ST_BADGE.draft

  const rejected = rawStatus === 'rejected' && !staged

  // ATT&CK technique: first mitre_id if present
  const attId = finding.mitre_ids?.[0] ?? null

  // host · confidence
  const confNum = finding.confidence_score != null
    ? Math.round(finding.confidence_score)
    : sev === 'HIGH' ? 92 : sev === 'MEDIUM' ? 74 : sev === 'LOW' ? 48 : null

  const meta = finding.host && confNum != null
    ? `${finding.host} · ${confNum}%`
    : finding.host ?? (confNum != null ? `${confNum}%` : '')

  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? 'true' : undefined}
      className={cn(
        'group relative flex w-full items-stretch gap-0 text-left text-xs transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
        active ? 'bg-[var(--bg-raised)]' : 'hover:bg-secondary/60',
        rejected && 'opacity-60',
      )}
      style={active ? { boxShadow: 'inset 2px 0 0 0 var(--orange)' } : undefined}
    >
      {/* Severity accent bar */}
      <span
        aria-hidden
        className="block shrink-0"
        style={{
          width: '3px',
          borderRadius: '0 2px 2px 0',
          background: conf ? conf.bg.replace('bg-', '').includes('sev-') ? `var(--${conf.bg.replace('bg-', '')})` : undefined : undefined,
          backgroundColor: sevMeta.color,
          opacity: 0.7,
          alignSelf: 'stretch',
        }}
      />

      <div className="flex flex-1 flex-col gap-0.5 overflow-hidden px-2.5 py-2.5">
        {/* ID row + ATT&CK chip */}
        <div className="flex items-center gap-1.5">
          {selectMode && (
            <span
              aria-hidden
              className={cn(
                'flex size-3.5 shrink-0 items-center justify-center rounded border',
                selected ? 'border-primary bg-primary text-primary-foreground' : 'border-border',
              )}
            >
              {selected && <Check className="size-2.5" />}
            </span>
          )}
          <span className="mono shrink-0 text-[10px] font-semibold" style={{ color: 'var(--text-muted)' }}>
            {finding.id}
          </span>
          {attId && (
            <span
              className="mono shrink-0 rounded border px-1 py-px text-[9px] font-semibold"
              style={{ borderColor: 'var(--border-hard)', color: 'var(--text-ghost)', background: 'transparent' }}
            >
              {attId}
            </span>
          )}
        </div>

        {/* Title */}
        <span className="truncate text-[12px] font-medium leading-snug" style={{ color: 'var(--text-bright)' }}>
          {finding.title}
        </span>

        {/* host · conf% */}
        {meta && (
          <span className="mono truncate text-[10px]" style={{ color: 'var(--text-ghost)' }}>
            {meta}
          </span>
        )}
      </div>

      {/* Dual letter badges: severity over status */}
      <div className="flex shrink-0 flex-col items-center justify-center gap-1 pr-2.5">
        <LetterBadge
          letter={sevMeta.letter}
          color={sevMeta.color}
          bg={`color-mix(in srgb,${sevMeta.color} 14%,transparent)`}
          title={`${sevMeta.label} severity`}
        />
        <LetterBadge
          letter={stMeta.letter}
          color={stMeta.color}
          bg={stMeta.bg}
          title={stMeta.label}
        />
      </div>
    </button>
  )
}

// ── ActivePill (host/account filter banners) ───────────────────────────

function ActivePill({ label, value, onClear }) {
  return (
    <div className="flex items-center justify-between border-b px-3 py-1.5 text-[11px]" style={{ borderColor: 'var(--border-soft)', background: 'color-mix(in srgb,var(--bg-raised) 60%,transparent)' }}>
      <span className="mono" style={{ color: 'var(--text-muted)' }}>
        {label}: <strong style={{ color: 'var(--text-bright)' }}>{value}</strong>
      </span>
      <button type="button" onClick={onClear} aria-label={`Clear ${label} filter`} className="text-muted-foreground hover:text-destructive">
        <X className="size-3" />
      </button>
    </div>
  )
}

// ── FindingsList export ────────────────────────────────────────────────

export function FindingsList({
  list,
  loading,
  counts,
  canReview,
  search: _search,
  onSearch: _onSearch,
  severityFilter,
  onClearSeverity,
  selectMode,
  onToggleSelectMode,
  selectedIds,
  onToggleSelectId,
  onBatch,
}) {
  const {
    findingsFilter,
    setFindingsFilter,
    findingsHostFilter,
    setFindingsHostFilter,
    findingsAccountFilter,
    setFindingsAccountFilter,
    selectedFindingId,
    setSelectedFindingId,
    delta,
  } = useStoreSlice((s) => ({
    findingsFilter: s.findingsFilter,
    setFindingsFilter: s.setFindingsFilter,
    findingsHostFilter: s.findingsHostFilter,
    setFindingsHostFilter: s.setFindingsHostFilter,
    findingsAccountFilter: s.findingsAccountFilter,
    setFindingsAccountFilter: s.setFindingsAccountFilter,
    selectedFindingId: s.selectedFindingId,
    setSelectedFindingId: s.setSelectedFindingId,
    delta: s.delta,
  }))

  const deltaById = useMemo(() => new Map((delta ?? []).map((d) => [d.id, d])), [delta])

  // Local sort state (pairs with findingsFilter for the filter panel)
  const [sortFilter, setSortFilter] = useState('newest')

  // Compute active filter count for badge
  const activeCount = [
    severityFilter ? 1 : 0,
    findingsFilter !== 'all' ? 1 : 0,
    sortFilter !== 'newest' ? 1 : 0,
  ].reduce((a, b) => a + b, 0)

  function clearAll() {
    setFindingsFilter('all')
    setSortFilter('newest')
    onClearSeverity?.()
  }

  // Sort the list by time
  const sortedList = useMemo(() => {
    const arr = list.slice()
    return arr.sort((a, b) => {
      const ta = new Date(a.modified_at || a.event_timestamp || 0).getTime()
      const tb = new Date(b.modified_at || b.event_timestamp || 0).getTime()
      return sortFilter === 'oldest' ? ta - tb : tb - ta
    })
  }, [list, sortFilter])

  function handleRowClick(f) {
    if (selectMode) onToggleSelectId(f.id)
    else setSelectedFindingId(f.id)
  }

  return (
    <div
      className="relative flex min-w-0 flex-col overflow-hidden border-r"
      style={{ borderColor: 'var(--border-soft)', background: 'var(--bg-surface)' }}
    >
      {/* Filter bar with dropdown */}
      <FilterBar
        shown={sortedList.length}
        sevFilter={severityFilter ?? 'ALL'}
        onSevFilter={(v) => {
          if (v === 'ALL') onClearSeverity?.()
          else {
            window.history.replaceState(null, '', `#/findings?sev=${v.toLowerCase()}`)
            window.dispatchEvent(new Event('hashchange'))
          }
        }}
        stateFilter={findingsFilter}
        onStateFilter={(v) => {
          setFindingsFilter(v)
          setSelectedFindingId(null)
        }}
        sortFilter={sortFilter}
        onSortFilter={setSortFilter}
        activeCount={activeCount}
        onClearAll={clearAll}
      />

      {findingsHostFilter && (
        <ActivePill label="Host" value={findingsHostFilter} onClear={() => setFindingsHostFilter(null)} />
      )}
      {findingsAccountFilter !== null && (
        <ActivePill
          label="Account"
          value={findingsAccountFilter === '' ? 'N/A' : findingsAccountFilter}
          onClear={() => setFindingsAccountFilter(null)}
        />
      )}

      {/* Scrollable rows */}
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="space-y-3 p-4">
            {[80, 65, 90, 55, 75].map((w, i) => (
              <Skeleton key={i} className="h-3" style={{ width: `${w}%` }} />
            ))}
          </div>
        ) : sortedList.length === 0 ? (
          <div className="flex flex-col items-center gap-1 p-8 text-center">
            <p className="text-xs text-muted-foreground">No findings match the current filters.</p>
            <p className="text-xs text-muted-foreground">Adjust the filter above.</p>
          </div>
        ) : (
          sortedList.map((f) => (
            <Row
              key={f.id}
              finding={f}
              active={f.id === selectedFindingId}
              selected={selectMode && selectedIds.has(f.id)}
              selectMode={selectMode}
              staged={deltaById.get(f.id)}
              onClick={() => handleRowClick(f)}
            />
          ))
        )}
      </div>

      {/* Footer counts + select toggle */}
      <div className="flex items-center justify-between border-t px-3 py-2 text-[11px]" style={{ borderColor: 'var(--border-soft)' }}>
        <span className="mono tnum" style={{ color: 'var(--text-muted)' }}>
          {counts.pending ?? 0} pending · {counts.reviewed ?? 0} reviewed
        </span>
        {canReview && (
          <button
            type="button"
            onClick={onToggleSelectMode}
            className={cn('mono text-[11px] font-semibold', selectMode ? 'text-primary' : 'text-muted-foreground hover:text-foreground')}
          >
            {selectMode ? 'Cancel' : 'Select'}
          </button>
        )}
      </div>

      {canReview && selectMode && selectedIds.size > 0 && (
        <div className="flex gap-2 border-t p-2" style={{ borderColor: 'var(--border-soft)' }}>
          <Button size="xs" onClick={() => onBatch('approve')} className="flex-1 gap-1 bg-status-approved text-primary-foreground hover:bg-status-approved/90">
            <Check className="size-3" /> Approve {selectedIds.size}
          </Button>
          <Button size="xs" variant="destructive" onClick={() => onBatch('reject')} className="flex-1 gap-1">
            <X className="size-3" /> Reject {selectedIds.size}
          </Button>
        </div>
      )}
    </div>
  )
}
