import { useMemo, useState } from 'react'
import { MonitorSmartphone } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { SkeletonBlock } from '@/components/common/Skeleton'
import { sortBy, displayHost } from '@/components/common/entity-utils'
import { EntityShell, EntityEmptyState } from '@/components/common/EntityShell'
import { EntityTable } from '@/components/common/EntityTable'
import { ConfidenceBadge, StatusSummary } from '@/components/common/EntityBadges'
import { useHostsData } from './useHostsData'

// ─────────────────────────────────────────────────────────────────────────
// HostsTab — "Hosts in Scope" registry (Mission-Control reskin of the legacy
// hosts view, full functional parity). One scroll owner (EntityShell). Each row
// aggregates a host's findings: counts, distinct accounts, best confidence,
// event time-range, status summary. Clicking a row sets the Findings host
// filter and jumps to Findings (legacy behaviour preserved).
//
// Parity + enhancement: legacy columns reproduced 1:1; columns are now sortable
// via the shared EntityTable (default by findings count, desc).
// Decomposed: useHostsData (derivation) · shared common/* primitives.
// ─────────────────────────────────────────────────────────────────────────

const COLUMNS = [
  { key: 'host', label: 'Host', sortable: true, nowrap: true },
  { key: 'findingsCount', label: 'Findings', sortable: true, align: 'right' },
  { key: 'accountsCount', label: 'Accounts', sortable: true, align: 'right' },
  { key: 'bestConfidence', label: 'Best Confidence', sortable: true },
  { key: 'timeRange', label: 'Time Range', sortable: true, nowrap: true },
  { key: 'statuses', label: 'Status Summary' },
]

const SORT_VALUE = {
  host: (r) => r.host,
  findingsCount: (r) => r.findingsCount,
  accountsCount: (r) => r.accountsCount,
  bestConfidence: (r) => r.bestConfidence,
  timeRange: (r) => r.timeRange,
}

export function HostsTab() {
  const { findings, setActiveTab, setFindingsHostFilter, isLoading } = useStoreSlice((s) => ({
    findings: s.findings,
    setActiveTab: s.setActiveTab,
    setFindingsHostFilter: s.setFindingsHostFilter,
    isLoading: s.isLoading,
  }))

  const hostsData = useHostsData(findings)
  const [sortKey, setSortKey] = useState('findingsCount')
  const [sortAsc, setSortAsc] = useState(false)

  const rows = useMemo(
    () => sortBy(hostsData, SORT_VALUE[sortKey] ?? SORT_VALUE.host, sortAsc),
    [hostsData, sortKey, sortAsc],
  )

  function handleSort(key) {
    if (key === sortKey) setSortAsc((v) => !v)
    else {
      setSortKey(key)
      setSortAsc(true)
    }
  }

  function handleRowClick(row) {
    setFindingsHostFilter(row.host)
    setActiveTab('findings')
  }

  if (isLoading) {
    return (
      <EntityShell title="Hosts in Scope" subtitle="Systems attributed in this case" ariaLabel="Hosts in scope">
        <SkeletonBlock rows={8} gap={12} />
      </EntityShell>
    )
  }

  function renderCell(row, key) {
    switch (key) {
      case 'host':
        return <span className="mono text-[13px] font-medium text-foreground">{displayHost(row.host)}</span>
      case 'findingsCount':
        return <span className="mono text-foreground">{row.findingsCount}</span>
      case 'accountsCount':
        return <span className="mono text-foreground">{row.accountsCount}</span>
      case 'bestConfidence':
        return <ConfidenceBadge confidence={row.bestConfidence} />
      case 'timeRange':
        return <span className="mono text-[11px] text-muted-foreground">{row.timeRange}</span>
      case 'statuses':
        return <StatusSummary statuses={row.statuses} />
      default:
        return null
    }
  }

  return (
    <EntityShell
      title="Hosts in Scope"
      subtitle="Systems attributed in this case"
      shownCount={rows.length}
      totalCount={hostsData.length}
      ariaLabel="Hosts in scope"
    >
      {hostsData.length === 0 ? (
        <EntityEmptyState
          icon={MonitorSmartphone}
          title="No hosts in scope yet."
          hint="Hosts appear here as findings are attributed to systems in the case."
        />
      ) : (
        <EntityTable
          caption="Hosts in scope"
          columns={COLUMNS}
          rows={rows}
          rowKey={(r) => r.host}
          renderCell={renderCell}
          sortKey={sortKey}
          sortAsc={sortAsc}
          onSort={handleSort}
          onRowClick={handleRowClick}
        />
      )}
    </EntityShell>
  )
}
