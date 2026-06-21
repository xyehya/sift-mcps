import { useMemo, useState } from 'react'

import { useStoreSlice } from '@/store/useStore'
import { SkeletonBlock } from '@/components/common/Skeleton'
import {
  filterTimeline,
  TIMELINE_TYPES,
  TIMELINE_TYPE_CLASS,
} from '@/components/common/entity-utils'
import { EntityShell, EntityEmptyState } from '@/components/common/EntityShell'
import { SearchInput, SelectFilter, ToggleChip, ResultCount } from '@/components/common/FilterBar'
import { Clock } from 'lucide-react'
import { TimelineEvent } from './TimelineEvent'

// ─────────────────────────────────────────────────────────────────────────
// TimelineTab — chronological event stream (Mission-Control reskin of the
// legacy timeline view, full functional parity). Filter bar: multi-select event
// type chips, host select, free-text search, and a live result count. The list
// is chronologically sorted with >30-min gap markers and per-day date
// separators; each row cross-links to its source/related findings and shows an
// approved check. One scroll owner (EntityShell). Filter/sort logic lives in
// entity-utils (filterTimeline) so it is unit-testable; the row is TimelineEvent.
// ─────────────────────────────────────────────────────────────────────────

// Static active-chip token-class bundle per type (JIT-safe — text colour from
// the shared map + a faint tinted fill + matching border).
const CHIP_ACTIVE = {
  auth: 'text-sev-med bg-sev-med/15 border-sev-med/40',
  execution: 'text-sev-high bg-sev-high/15 border-sev-high/40',
  process: 'text-sev-high bg-sev-high/15 border-sev-high/40',
  file: 'text-steel bg-steel/15 border-steel/40',
  network: 'text-violet bg-violet/15 border-violet/40',
  persistence: 'text-status-approved bg-status-approved/15 border-status-approved/40',
  registry: 'text-foreground bg-muted/60 border-border-hard',
  lateral: 'text-sev-high bg-sev-high/15 border-sev-high/40',
  other: 'text-foreground bg-muted/40 border-border-hard',
}

export function TimelineTab() {
  const { timeline, setSelectedFindingId, setActiveTab, isLoading } = useStoreSlice((s) => ({
    timeline: s.timeline,
    setSelectedFindingId: s.setSelectedFindingId,
    setActiveTab: s.setActiveTab,
    isLoading: s.isLoading,
  }))

  const [typeFilter, setTypeFilter] = useState(() => new Set())
  const [hostFilter, setHostFilter] = useState('all')
  const [search, setSearch] = useState('')

  const hostOptions = useMemo(() => {
    const hosts = [...new Set((timeline ?? []).map((e) => e.host).filter(Boolean))]
    return [{ value: 'all', label: 'all hosts' }, ...hosts.map((h) => ({ value: h, label: h }))]
  }, [timeline])

  const filtered = useMemo(
    () => filterTimeline(timeline, { types: typeFilter, host: hostFilter, search }),
    [timeline, typeFilter, hostFilter, search],
  )

  function toggleType(t) {
    setTypeFilter((prev) => {
      const next = new Set(prev)
      if (next.has(t)) next.delete(t)
      else next.add(t)
      return next
    })
  }

  function navigateToFinding(fid) {
    if (!fid) return
    setSelectedFindingId(fid)
    setActiveTab('findings')
  }

  const filterBar = (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-1">
        {TIMELINE_TYPES.map((t) => (
          <ToggleChip
            key={t}
            active={typeFilter.has(t)}
            onClick={() => toggleType(t)}
            activeClass={CHIP_ACTIVE[t]}
          >
            <span className={typeFilter.has(t) ? undefined : TIMELINE_TYPE_CLASS[t]}>{t}</span>
          </ToggleChip>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <SelectFilter value={hostFilter} onChange={setHostFilter} options={hostOptions} label="Filter by host" />
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search events…"
          label="Search timeline events"
          className="min-w-[160px] flex-1"
        />
        <ResultCount>{filtered.length} events</ResultCount>
      </div>
    </div>
  )

  if (isLoading) {
    return (
      <EntityShell title="Timeline" ariaLabel="Investigation timeline">
        <SkeletonBlock rows={12} gap={10} />
      </EntityShell>
    )
  }

  return (
    <EntityShell title="Timeline" filterBar={filterBar} ariaLabel="Investigation timeline">
      {filtered.length === 0 ? (
        <EntityEmptyState
          icon={Clock}
          title="No events match filters."
          hint="Adjust the type, host, or search filters to widen the window."
        />
      ) : (
        <div className="space-y-px">
          {filtered.map((ev, i) => {
            const prev = filtered[i - 1]
            const showDateSep =
              i === 0 ||
              new Date(ev.timestamp).toDateString() !== new Date(filtered[i - 1].timestamp).toDateString()
            return (
              <TimelineEvent
                key={ev.id}
                ev={ev}
                prev={prev}
                showDateSep={showDateSep}
                onNavigate={navigateToFinding}
              />
            )
          })}
        </div>
      )}
    </EntityShell>
  )
}
