import { useMemo } from 'react'

import {
  displayHost,
  bestConfidence,
  statusSummary,
  timeRange,
  getAccountsForFinding,
} from '@/components/common/entity-utils'

// ─────────────────────────────────────────────────────────────────────────
// useAccountsData — derives per-account rows from findings (legacy AccountsTab
// parity). Findings carrying one or more accounts are grouped per account;
// findings with no attributed account fall into the 'N/A' (Unattributed) bucket.
// Also exposes the single-host detection that drives column collapsing.
// ─────────────────────────────────────────────────────────────────────────

export function useAccountsData(findings) {
  const uniqueHosts = useMemo(
    () => [...new Set((findings ?? []).map((f) => f.host).filter(Boolean).map((h) => h.toUpperCase()))],
    [findings],
  )
  const isSingleHost = uniqueHosts.length === 1
  const singleHostName = isSingleHost ? displayHost(uniqueHosts[0]) : null

  const accountsData = useMemo(() => {
    const groups = {}
    for (const f of findings ?? []) {
      const accs = getAccountsForFinding(f)
      if (accs.length === 0) {
        ;(groups['N/A'] ??= []).push(f)
      } else {
        for (const acc of accs) (groups[acc] ??= []).push(f)
      }
    }

    return Object.entries(groups).map(([account, list]) => {
      const hostsSet = new Set()
      for (const f of list) {
        const host = (f.host ?? '').trim()
        if (host) hostsSet.add(displayHost(host))
      }
      const hosts = [...hostsSet].sort()
      return {
        account,
        findingsCount: list.length,
        hosts,
        hostCount: hosts.length,
        bestConfidence: bestConfidence(list),
        timeRange: timeRange(list),
        statuses: statusSummary(list),
        isNa: account === 'N/A',
      }
    })
  }, [findings])

  return { accountsData, isSingleHost, singleHostName }
}
