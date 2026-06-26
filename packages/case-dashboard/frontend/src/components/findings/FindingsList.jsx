import { useMemo, useState } from 'react'
import { Check, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { FilterBar } from '@/components/findings/FindingsFilterBar'
import { Row, ActivePill } from '@/components/findings/FindingRow'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'

// ─────────────────────────────────────────────────────────────────────────
// Findings list (handoff §"Left pane") — unified filter-dropdown (replaces
// old tab-strip) + scrollable rows with severity accent bar, ATT&CK chip,
// dual letter badges (sev + status). Receives the already-filtered `list`
// from FindingsTab (which also drives keyboard nav over the same list). The
// filter bar and rows live in sibling modules (FindingsFilterBar / FindingRow)
// to keep this file under §7's ceiling.
// ─────────────────────────────────────────────────────────────────────────

export function FindingsList({
  list,
  loading,
  counts,
  canReview,
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
    <div className="relative flex min-w-0 flex-col overflow-hidden border-r border-border-soft bg-bg-surface">
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
              // Data-driven numeric width per skeleton placeholder.
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
      <div className="flex items-center justify-between border-t border-border-soft px-3 py-2 text-[11px]">
        <span className="mono tnum text-text-muted">
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
        <div className="flex gap-2 border-t border-border-soft p-2">
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
