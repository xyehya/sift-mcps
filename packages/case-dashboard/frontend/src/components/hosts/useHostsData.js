import { useMemo } from 'react'

import {
  displayHost,
  bestConfidence,
  statusSummary,
  timeRange,
  getAccountsForFinding,
} from '@/components/common/entity-utils'

// ─────────────────────────────────────────────────────────────────────────
// useHostsData — derives the per-host rows from the findings list (legacy
// HostsTab parity). For each host: findings count, distinct-account count,
// best confidence, event time-range, and the draft/approved/rejected summary.
// Pure derivation memoized off `findings`; no store writes here.
// ─────────────────────────────────────────────────────────────────────────

export function useHostsData(findings) {
  return useMemo(() => {
    const groups = {}
    for (const f of findings ?? []) {
      if (!f.host) continue
      const host = displayHost(f.host)
      ;(groups[host] ??= []).push(f)
    }

    return Object.entries(groups).map(([host, list]) => {
      const accountsSet = new Set()
      for (const f of list) {
        for (const a of getAccountsForFinding(f)) accountsSet.add(a)
      }
      return {
        host,
        findingsCount: list.length,
        accountsCount: accountsSet.size,
        bestConfidence: bestConfidence(list),
        timeRange: timeRange(list),
        statuses: statusSummary(list),
      }
    })
  }, [findings])
}
