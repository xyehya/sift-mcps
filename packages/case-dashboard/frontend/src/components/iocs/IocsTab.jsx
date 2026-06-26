import { useMemo, useState } from 'react'
import { Crosshair } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { SkeletonBlock } from '@/components/common/Skeleton'
import { displayHost } from '@/components/common/entity-utils'
import { EntityShell, EntityEmptyState } from '@/components/common/EntityShell'
import { SearchInput, SelectFilter } from '@/components/common/FilterBar'
import { iocCategories, filterIocs } from './iocs-utils'
import { IocRow } from './IocRow'

// ─────────────────────────────────────────────────────────────────────────
// IocsTab — Indicators of Compromise registry (Mission-Control reskin of the
// legacy IOC view, full functional parity). Filter bar: free-text search
// (value/id/type), category select (derived from data), status select. Table:
// expandable rows (MITRE techniques · tags · provenance footer), per-value copy,
// confidence + status badges, sighting-host chips, and source-finding deep
// links. Single-host cases collapse the Hosts column and annotate the title.
// One scroll owner (EntityShell). Filter logic lives in iocs-utils
// (unit-testable); each row is IocRow. The mock/real split lives at the API
// adapter layer, never in component handlers (§3).
// ─────────────────────────────────────────────────────────────────────────

const STATUS_OPTIONS = [
  { value: 'all', label: 'All Status' },
  { value: 'DRAFT', label: 'DRAFT' },
  { value: 'APPROVED', label: 'APPROVED' },
  { value: 'REJECTED', label: 'REJECTED' },
]

const HEADERS_BASE = ['', 'Value', 'Type', 'Category', 'Confidence']
const HEADERS_TAIL = ['Source Findings', 'Status']

export function IocsTab() {
  const { iocs, findings, setActiveTab, setSelectedFindingId, isLoading } = useStoreSlice((s) => ({
    iocs: s.iocs,
    findings: s.findings,
    setActiveTab: s.setActiveTab,
    setSelectedFindingId: s.setSelectedFindingId,
    isLoading: s.isLoading,
  }))

  const [categoryFilter, setCategoryFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [expandedRows, setExpandedRows] = useState(() => new Set())

  const uniqueHosts = useMemo(
    () => [...new Set((findings ?? []).map((f) => f.host).filter(Boolean).map((h) => h.toUpperCase()))],
    [findings],
  )
  const isSingleHost = uniqueHosts.length === 1
  const singleHostName = isSingleHost ? displayHost(uniqueHosts[0]) : null

  const categoryOptions = useMemo(
    () => [{ value: 'all', label: 'All Categories' }, ...iocCategories(iocs).map((c) => ({ value: c, label: c }))],
    [iocs],
  )

  const filtered = useMemo(
    () => filterIocs(iocs, { category: categoryFilter, status: statusFilter, search }),
    [iocs, categoryFilter, statusFilter, search],
  )

  function toggleRow(id) {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function handleFindingClick(fid) {
    if (!fid) return
    setSelectedFindingId(fid)
    setActiveTab('findings')
  }

  async function handleCopy(value) {
    try {
      await navigator.clipboard?.writeText(value)
    } catch {
      // clipboard unavailable — silently ignore (legacy parity).
    }
  }

  const colSpan = isSingleHost ? 7 : 8
  const headers = isSingleHost
    ? [...HEADERS_BASE, ...HEADERS_TAIL]
    : [...HEADERS_BASE, 'Hosts', ...HEADERS_TAIL]

  const subtitle = isSingleHost
    ? `Host: ${singleHostName}`
    : 'Extracted from approved findings'

  const filterBar = (
    <div className="flex flex-wrap items-center gap-2">
      <SearchInput
        value={search}
        onChange={setSearch}
        placeholder="Search IOCs…"
        label="Search indicators of compromise"
        className="w-52"
      />
      <SelectFilter value={categoryFilter} onChange={setCategoryFilter} options={categoryOptions} label="Filter by category" />
      <SelectFilter value={statusFilter} onChange={setStatusFilter} options={STATUS_OPTIONS} label="Filter by status" />
    </div>
  )

  if (isLoading) {
    return (
      <EntityShell title="Indicators of Compromise" subtitle="Extracted from approved findings" ariaLabel="Indicators of compromise">
        <SkeletonBlock rows={10} gap={12} />
      </EntityShell>
    )
  }

  return (
    <EntityShell
      title="Indicators of Compromise"
      subtitle={subtitle}
      shownCount={filtered.length}
      totalCount={iocs.length}
      filterBar={filterBar}
      ariaLabel="Indicators of compromise"
    >
      {filtered.length === 0 ? (
        <EntityEmptyState
          icon={Crosshair}
          title="No IOCs match the current filters."
          hint="Indicators are extracted from approved findings; adjust the filters to widen the set."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border-soft bg-card">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-border-soft bg-secondary/40">
                {headers.map((h, i) => (
                  <th
                    key={h || `col-${i}`}
                    scope="col"
                    className="mono whitespace-nowrap px-4 py-2.5 text-[10px] font-semibold uppercase tracking-[.1em] text-muted-foreground"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-faint">
              {filtered.map((ioc) => (
                <IocRow
                  key={ioc.id}
                  ioc={ioc}
                  isExpanded={expandedRows.has(ioc.id)}
                  isSingleHost={isSingleHost}
                  colSpan={colSpan}
                  onToggle={toggleRow}
                  onCopy={handleCopy}
                  onFindingClick={handleFindingClick}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </EntityShell>
  )
}
