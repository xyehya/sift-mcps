import { useMemo } from 'react'
import { Check, Search, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { confClass, FILTERS } from '@/components/findings/findings-utils'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'

// ─────────────────────────────────────────────────────────────────────────
// Findings list — search + status filter chips + active host/account filter
// pills + the scrollable finding rows + footer counts + (examiner-only) bulk
// select toolbar. Reads filter/selection/delta from the store; receives the
// already-filtered `list`, search value and select-mode state from the tab
// (which also drives keyboard nav over the same filtered list).
// ─────────────────────────────────────────────────────────────────────────

function FilterChips({ filter, onFilter }) {
  return (
    <div className="flex border-b border-border" role="tablist" aria-label="Status filter">
      {FILTERS.map((f) => (
        <button
          key={f}
          role="tab"
          aria-selected={filter === f}
          onClick={() => onFilter(f)}
          className={cn(
            'flex-1 py-2 text-[11px] font-semibold uppercase tracking-wider capitalize transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
            filter === f ? 'border-b-2 border-primary text-primary' : 'text-muted-foreground hover:text-foreground',
          )}
        >
          {f}
        </button>
      ))}
    </div>
  )
}

function ActivePill({ label, value, onClear }) {
  return (
    <div className="flex items-center justify-between border-b border-border bg-secondary/50 px-3 py-1.5 text-[11px]">
      <span className="mono text-muted-foreground">
        {label}: <strong className="text-foreground">{value}</strong>
      </span>
      <button type="button" onClick={onClear} aria-label={`Clear ${label} filter`} className="text-muted-foreground hover:text-destructive">
        <X className="size-3" />
      </button>
    </div>
  )
}

function Row({ finding, active, selected, selectMode, staged, onClick }) {
  const conf = confClass(finding.confidence)
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? 'true' : undefined}
      className={cn(
        'flex w-full items-start gap-2 px-3 py-2.5 text-left text-xs transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
        active ? 'bg-secondary' : 'hover:bg-secondary/60',
      )}
    >
      {selectMode && (
        <span
          aria-hidden
          className={cn(
            'mt-0.5 flex size-3.5 shrink-0 items-center justify-center rounded border',
            selected ? 'border-primary bg-primary text-primary-foreground' : 'border-border',
          )}
        >
          {selected && <Check className="size-2.5" />}
        </span>
      )}
      <span aria-hidden className={cn('mt-1 size-1.5 shrink-0 rounded-full', conf ? conf.bg : 'bg-muted-foreground')} />
      <span className="mono shrink-0 text-muted-foreground">{finding.id}</span>
      <span className="flex-1 truncate text-foreground">{finding.title}</span>
      {staged && (
        <span className={cn('shrink-0 text-[10px] font-semibold', staged.action === 'approve' ? 'text-status-approved' : 'text-status-rejected')}>
          {staged.action === 'approve' ? '✓' : staged.action === 'reject' ? '✗' : '✎'}
        </span>
      )}
    </button>
  )
}

export function FindingsList({
  list,
  loading,
  counts,
  canReview,
  search,
  onSearch,
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

  function handleRowClick(f) {
    if (selectMode) onToggleSelectId(f.id)
    else setSelectedFindingId(f.id)
  }

  return (
    <div className="flex w-72 shrink-0 flex-col overflow-hidden border-r border-border bg-card">
      <div className="border-b border-border p-3">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={search}
            onChange={(e) => onSearch(e.target.value)}
            placeholder="Search findings…"
            aria-label="Search findings"
            className="h-8 pl-8 text-xs"
          />
        </div>
      </div>

      <FilterChips
        filter={findingsFilter}
        onFilter={(f) => {
          setFindingsFilter(f)
          setSelectedFindingId(null)
        }}
      />

      {findingsHostFilter && <ActivePill label="Host" value={findingsHostFilter} onClear={() => setFindingsHostFilter(null)} />}
      {findingsAccountFilter !== null && (
        <ActivePill
          label="Account"
          value={findingsAccountFilter === '' ? 'N/A' : findingsAccountFilter}
          onClear={() => setFindingsAccountFilter(null)}
        />
      )}

      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="space-y-3 p-4">
            {[80, 65, 90, 55, 75].map((w, i) => (
              <Skeleton key={i} className="h-3" style={{ width: `${w}%` }} />
            ))}
          </div>
        ) : list.length === 0 ? (
          <div className="flex flex-col items-center gap-1 p-8 text-center">
            <p className="text-xs text-muted-foreground">No {findingsFilter === 'all' ? '' : findingsFilter} findings.</p>
            <p className="text-[11px] text-muted-foreground/70">Adjust the filter or search above.</p>
          </div>
        ) : (
          list.map((f) => (
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

      <div className="flex items-center justify-between border-t border-border px-3 py-2 text-[11px] text-muted-foreground">
        <span className="tnum">
          {counts.pending} pending · {counts.reviewed} reviewed
        </span>
        {canReview && (
          <button
            type="button"
            onClick={onToggleSelectMode}
            className={cn('font-semibold', selectMode ? 'text-primary' : 'text-muted-foreground hover:text-foreground')}
          >
            {selectMode ? 'Cancel' : 'Select'}
          </button>
        )}
      </div>

      {canReview && selectMode && selectedIds.size > 0 && (
        <div className="flex gap-2 border-t border-border p-2">
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
