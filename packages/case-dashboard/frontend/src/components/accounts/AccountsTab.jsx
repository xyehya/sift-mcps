import { useMemo, useState } from 'react'
import { Users } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { SkeletonBlock } from '@/components/common/Skeleton'
import { sortBy } from '@/components/common/entity-utils'
import { EntityShell, EntityEmptyState, ChipList } from '@/components/common/EntityShell'
import { EntityTable } from '@/components/common/EntityTable'
import { ConfidenceBadge, StatusSummary } from '@/components/common/EntityBadges'
import { useAccountsData } from './useAccountsData'

// ─────────────────────────────────────────────────────────────────────────
// AccountsTab — "Accounts in Scope" registry (Mission-Control reskin of the
// legacy accounts view, full functional parity). Groups findings by attributed
// account; findings with no account fall into an italic "Unattributed Account"
// bucket. Single-host cases collapse the Hosts / Host-List columns (legacy
// behaviour) and append "— Host: X" to the title. Row click sets the Findings
// account filter ('' for the N/A bucket) and jumps to Findings.
//
// Parity + enhancement: legacy columns reproduced 1:1; sortable via EntityTable.
// Decomposed: useAccountsData (derivation) · shared common/* primitives.
// ─────────────────────────────────────────────────────────────────────────

function buildColumns(isSingleHost) {
  return [
    { key: 'account', label: 'Account', sortable: true },
    { key: 'findingsCount', label: 'Findings', sortable: true, align: 'right' },
    ...(isSingleHost
      ? []
      : [
          { key: 'hostCount', label: 'Hosts', sortable: true, align: 'right' },
          { key: 'hosts', label: 'Host List' },
        ]),
    { key: 'bestConfidence', label: 'Best Confidence', sortable: true },
    { key: 'timeRange', label: 'Time Range', sortable: true, nowrap: true },
    { key: 'statuses', label: 'Status Summary' },
  ]
}

const SORT_VALUE = {
  account: (r) => r.account,
  findingsCount: (r) => r.findingsCount,
  hostCount: (r) => r.hostCount,
  bestConfidence: (r) => r.bestConfidence,
  timeRange: (r) => r.timeRange,
}

export function AccountsTab() {
  const { findings, setActiveTab, setFindingsAccountFilter, isLoading } = useStoreSlice((s) => ({
    findings: s.findings,
    setActiveTab: s.setActiveTab,
    setFindingsAccountFilter: s.setFindingsAccountFilter,
    isLoading: s.isLoading,
  }))

  const { accountsData, isSingleHost, singleHostName } = useAccountsData(findings)
  const [sortKey, setSortKey] = useState('findingsCount')
  const [sortAsc, setSortAsc] = useState(false)

  const columns = useMemo(() => buildColumns(isSingleHost), [isSingleHost])
  const rows = useMemo(
    () => sortBy(accountsData, SORT_VALUE[sortKey] ?? SORT_VALUE.account, sortAsc),
    [accountsData, sortKey, sortAsc],
  )

  function handleSort(key) {
    if (key === sortKey) setSortAsc((v) => !v)
    else {
      setSortKey(key)
      setSortAsc(true)
    }
  }

  function handleRowClick(row) {
    setFindingsAccountFilter(row.isNa ? '' : row.account)
    setActiveTab('findings')
  }

  const title = `Accounts in Scope${isSingleHost ? ` — Host: ${singleHostName}` : ''}`

  if (isLoading) {
    return (
      <EntityShell title="Accounts in Scope" ariaLabel="Accounts in scope">
        <SkeletonBlock rows={8} gap={12} />
      </EntityShell>
    )
  }

  function renderCell(row, key) {
    switch (key) {
      case 'account':
        return row.isNa ? (
          <span className="italic text-muted-foreground">Unattributed Account</span>
        ) : (
          <span className="mono font-semibold text-foreground">{row.account}</span>
        )
      case 'findingsCount':
        return <span className="mono text-foreground">{row.findingsCount}</span>
      case 'hostCount':
        return <span className="mono text-foreground">{row.hostCount}</span>
      case 'hosts':
        return <ChipList items={row.hosts} max />
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
    <EntityShell title={title} count={accountsData.length} ariaLabel="Accounts in scope">
      {accountsData.length === 0 ? (
        <EntityEmptyState
          icon={Users}
          title="No accounts in scope yet."
          hint="Accounts appear here as findings attribute activity to user or service accounts."
        />
      ) : (
        <EntityTable
          caption="Accounts in scope"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.account}
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
