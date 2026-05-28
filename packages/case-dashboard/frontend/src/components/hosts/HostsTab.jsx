import { useMemo } from 'react'
import { useStore } from '../../store/useStore'
import { SkeletonBlock } from '../common/Skeleton'

const CONF_COLOR = {
  HIGH:        'var(--crimson)',
  MEDIUM:      'var(--amber)',
  LOW:         'var(--cyan)',
  SPECULATIVE: 'var(--violet)',
}

const CONF_SHAPE = { HIGH: '▲', MEDIUM: '◆', LOW: '●', SPECULATIVE: '◇' }

function getAccountsForFinding(f) {
  const raw = f.affected_account || f.account
  if (!raw) return []
  if (Array.isArray(raw)) {
    return raw.map(a => typeof a === 'string' ? a.trim() : (a.value ?? '')).filter(Boolean)
  }
  if (typeof raw === 'string') {
    return raw.split(',').map(s => s.trim()).filter(Boolean)
  }
  return []
}

export function HostsTab() {
  const { findings, setActiveTab, setFindingsHostFilter, isLoading } = useStore()

  const hostsData = useMemo(() => {
    const groups = {}
    for (const f of findings) {
      const rawHost = f.host
      if (!rawHost) continue
      const host = rawHost.toUpperCase()
      if (!groups[host]) {
        groups[host] = []
      }
      groups[host].push(f)
    }

    return Object.entries(groups).map(([host, list]) => {
      const findingsCount = list.length

      const accountsSet = new Set()
      for (const f of list) {
        const accs = getAccountsForFinding(f)
        for (const a of accs) {
          accountsSet.add(a)
        }
      }
      const accountsCount = accountsSet.size

      const CONF_WEIGHTS = { HIGH: 4, MEDIUM: 3, LOW: 2, SPECULATIVE: 1 }
      let bestConf = 'SPECULATIVE'
      let maxWeight = 0
      for (const f of list) {
        const conf = (f.confidence ?? '').toUpperCase()
        const weight = CONF_WEIGHTS[conf] ?? 0
        if (weight > maxWeight) {
          maxWeight = weight
          bestConf = f.confidence
        }
      }

      let minMs = Infinity
      let maxMs = -Infinity
      let hasValidTime = false
      for (const f of list) {
        const rawTs = f.event_timestamp || f.timestamp
        if (rawTs) {
          const ms = new Date(rawTs).getTime()
          if (!isNaN(ms)) {
            hasValidTime = true
            if (ms < minMs) minMs = ms
            if (ms > maxMs) maxMs = ms
          }
        }
      }

      let timeRange = '—'
      if (hasValidTime) {
        const minStr = new Date(minMs).toISOString().replace('T', ' ').substring(0, 19)
        const maxStr = new Date(maxMs).toISOString().replace('T', ' ').substring(0, 19)
        timeRange = minStr === maxStr ? minStr : `${minStr} to ${maxStr}`
      }

      const statuses = { draft: 0, approved: 0, rejected: 0 }
      for (const f of list) {
        const st = (f.status ?? 'draft').toLowerCase()
        if (st === 'draft') statuses.draft++
        else if (st === 'approved') statuses.approved++
        else if (st === 'rejected') statuses.rejected++
        else statuses.draft++
      }

      return {
        host,
        findingsCount,
        accountsCount,
        bestConfidence: bestConf,
        timeRange,
        statuses,
      }
    })
  }, [findings])

  function handleRowClick(host) {
    setFindingsHostFilter(host)
    setActiveTab('findings')
  }

  if (isLoading) {
    return (
      <div className="h-full overflow-y-auto p-5 space-y-4" style={{ background: 'var(--bg-base)' }}>
        <div className="pb-2 border-b" style={{ borderColor: 'var(--border-faint)' }}>
          <h1 className="font-display font-bold text-lg" style={{ color: 'var(--text-bright)' }}>Hosts</h1>
        </div>
        <SkeletonBlock rows={8} gap={12} />
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto p-5 space-y-4 flex flex-col" style={{ background: 'var(--bg-base)' }}>
      {/* Header */}
      <div className="shrink-0 flex justify-between items-center pb-2 border-b" style={{ borderColor: 'var(--border-faint)' }}>
        <div className="flex items-baseline gap-2">
          <h1 className="font-display font-bold text-lg" style={{ color: 'var(--text-bright)' }}>Hosts in Scope</h1>
          <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
            ({hostsData.length} total)
          </span>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-x-auto min-h-0">
        {hostsData.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-12 h-12 mb-3 opacity-40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="2" y="3" width="20" height="14" rx="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
            <p className="font-mono text-sm">No hosts in scope yet.</p>
          </div>
        ) : (
          <table className="w-full text-left text-xs" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-soft)', color: 'var(--text-muted)' }}>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Host</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px] text-right">Findings</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px] text-right">Accounts</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Best Confidence</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Time Range</th>
                <th className="py-2.5 font-sans font-semibold uppercase tracking-wider text-[10px]">Status Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y" style={{ divideColor: 'var(--border-faint)' }}>
              {hostsData.map(({ host, findingsCount, accountsCount, bestConfidence, timeRange, statuses }) => {
                const confColor = CONF_COLOR[bestConfidence] ?? 'var(--text-muted)'
                return (
                  <tr
                    key={host}
                    onClick={() => handleRowClick(host)}
                    className="hover:bg-bg-raised transition-colors cursor-pointer"
                    style={{ color: 'var(--text-primary)' }}
                  >
                    <td className="py-3 pr-4 font-mono font-semibold" style={{ color: 'var(--text-bright)' }}>
                      {host}
                    </td>
                    <td className="py-3 pr-4 font-mono text-right" style={{ color: 'var(--text-primary)' }}>
                      {findingsCount}
                    </td>
                    <td className="py-3 pr-4 font-mono text-right" style={{ color: 'var(--text-primary)' }}>
                      {accountsCount}
                    </td>
                    <td className="py-3 pr-4">
                      <Badge color={confColor}>
                        {CONF_SHAPE[bestConfidence] || '◇'} {bestConfidence}
                      </Badge>
                    </td>
                    <td className="py-3 pr-4 font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                      {timeRange}
                    </td>
                    <td className="py-3">
                      <div className="flex flex-wrap gap-1.5">
                        {statuses.approved > 0 && (
                          <Badge color="var(--jade)">{statuses.approved} Approved</Badge>
                        )}
                        {statuses.draft > 0 && (
                          <Badge color="var(--amber)">{statuses.draft} Draft</Badge>
                        )}
                        {statuses.rejected > 0 && (
                          <Badge color="var(--crimson)">{statuses.rejected} Rejected</Badge>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function Badge({ color, children }) {
  return (
    <span
      className="px-1.5 py-0.5 rounded font-mono text-[10px] tracking-wider uppercase inline-flex items-center"
      style={{
        color,
        background: color + '1a',
        border: `1px solid ${color}33`,
      }}
    >
      {children}
    </span>
  )
}
