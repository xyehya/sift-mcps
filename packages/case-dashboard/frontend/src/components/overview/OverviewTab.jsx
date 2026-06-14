import { useMemo, useState } from 'react'
import { useStoreSlice } from '../../store/useStore'
import { Skeleton } from '../common/Skeleton'
import { CaseBriefCard } from './CaseBriefCard'
import { formatDistanceToNow } from 'date-fns'

const CONFIDENCE_COLORS = {
  HIGH:        'var(--crimson)',
  MEDIUM:      'var(--amber)',
  LOW:         'var(--cyan)',
  SPECULATIVE: 'var(--violet)',
}

export function OverviewTab() {
  const { activeCase, summary, findings, reports, delta, isLoading, setActiveTab, setFindingsFilter, setCommitDrawerOpen, setSelectedFindingId } = useStoreSlice((state) => ({
    activeCase: state.activeCase,
    summary: state.summary,
    findings: state.findings,
    reports: state.reports,
    delta: state.delta,
    isLoading: state.isLoading,
    setActiveTab: state.setActiveTab,
    setFindingsFilter: state.setFindingsFilter,
    setCommitDrawerOpen: state.setCommitDrawerOpen,
    setSelectedFindingId: state.setSelectedFindingId,
  }))
  const [bannerExpanded, setBannerExpanded] = useState(false)

  const findingStats = useMemo(() => {
    const stats = {
      approvedFallback: 0,
      pendingFallback: 0,
      highCount: 0,
      medCount: 0,
      lowCount: 0,
      specCount: 0,
      mitreIds: [],
    }
    const mitreIds = new Set()
    for (const finding of findings) {
      const status = finding.status
      if (status === 'approved' || status === 'APPROVED') stats.approvedFallback += 1
      if (status === 'draft' || status === 'DRAFT') stats.pendingFallback += 1

      const confidence = (finding.confidence ?? '').toUpperCase()
      if (confidence === 'HIGH') stats.highCount += 1
      if (confidence === 'MEDIUM') stats.medCount += 1
      if (confidence === 'LOW') stats.lowCount += 1
      if (confidence === 'SPECULATIVE') stats.specCount += 1

      for (const mitreId of finding.mitre_ids ?? []) {
        mitreIds.add(mitreId)
      }
    }
    stats.mitreIds = [...mitreIds]
    return stats
  }, [findings])

  // API shape: { findings: { total, by_status: {DRAFT, APPROVED, REJECTED} }, timeline, evidence, todos }
  const fstats    = summary?.findings ?? {}
  const byStatus  = fstats.by_status ?? {}
  const total     = fstats.total     ?? findings.length
  const approved  = byStatus.approved  ?? byStatus.APPROVED  ?? findingStats.approvedFallback
  const pending   = byStatus.draft     ?? byStatus.DRAFT     ?? findingStats.pendingFallback
  const staged    = delta.length
  const reviewPct = findings.length > 0 ? Math.round((delta.length / findings.length) * 100) : 0

  const highCount = findingStats.highCount
  const medCount  = findingStats.medCount
  const lowCount  = findingStats.lowCount
  const specCount = findingStats.specCount
  const maxCount  = Math.max(highCount, medCount, lowCount, specCount, 1)
  const mitreIds = findingStats.mitreIds

  return (
    <div className="h-full overflow-y-auto p-5" style={{ background: 'var(--bg-base)' }}>
      {/* Case banner */}
      {activeCase && (
        <button
          onClick={() => setBannerExpanded(!bannerExpanded)}
          className="mb-4 w-full text-left px-4 py-2.5 rounded text-xs font-mono cursor-pointer transition-colors"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}
        >
          <div className="flex items-center gap-3">
            <span style={{ color: 'var(--text-muted)' }}>CASE</span>
            <span style={{ color: 'var(--text-bright)' }}>{activeCase.case_id}</span>
            {activeCase.name && activeCase.name !== activeCase.case_id && (
              <>
                <span style={{ color: 'var(--border-hard)' }}>·</span>
                <span style={{ color: 'var(--text-primary)' }}>{activeCase.name}</span>
              </>
            )}
            <span
              className="ml-auto inline-flex items-center justify-center transition-transform"
              style={{
                color: 'var(--text-muted)', fontSize: '10px',
                width: '22px', height: '20px',
                transform: bannerExpanded ? 'rotate(180deg)' : undefined,
              }}
            >
              ▾
            </span>
            <span className="px-1.5 py-0.5 rounded text-[10px]"
              style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>
              ACTIVE
            </span>
          </div>
          {bannerExpanded && (
            <div className="mt-2 pt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5"
              style={{ borderTop: '1px solid var(--border-faint)' }}>
              <span style={{ color: 'var(--text-muted)' }}>name</span>
              <span style={{ color: 'var(--text-primary)' }}>{activeCase.name ?? '—'}</span>
              <span style={{ color: 'var(--text-muted)' }}>title</span>
              <span style={{ color: 'var(--text-primary)' }}>{activeCase.title ?? '—'}</span>
              <span style={{ color: 'var(--text-muted)' }}>status</span>
              <span style={{ color: 'var(--text-primary)' }}>{activeCase.status ?? '—'}</span>
              <span style={{ color: 'var(--text-muted)' }}>examiner</span>
              <span style={{ color: 'var(--text-primary)' }}>{activeCase.examiner ?? '—'}</span>
              <span style={{ color: 'var(--text-muted)' }}>created</span>
              <span style={{ color: 'var(--text-primary)' }}>{activeCase.created ?? '—'}</span>
            </div>
          )}
        </button>
      )}

      {/* Case brief (intake scope + objectives; examiner-editable) */}
      <CaseBriefCard />

      {/* KPI row */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        <KPICard label="FINDINGS" value={total} color="var(--cyan)" loading={isLoading} />
        <KPICard label="APPROVED" value={approved} color="var(--jade)" loading={isLoading}
          onClick={() => { setActiveTab('findings'); setFindingsFilter('approved') }} />
        <KPICard label="PENDING" value={pending} color="var(--amber)" loading={isLoading}
          onClick={() => { setActiveTab('findings'); setFindingsFilter('pending') }} />
        <KPICard
          label="STAGED"
          value={`${staged}`}
          color="var(--status-staged)"
          loading={isLoading}
          onClick={() => staged > 0 && setCommitDrawerOpen(true)}
          extra={
            <div className="mt-2 h-1 rounded-full overflow-hidden" style={{ background: 'var(--bg-raised)' }}>
              <div className="h-full rounded-full transition-all"
                style={{ width: `${reviewPct}%`, background: 'var(--status-staged)' }} />
            </div>
          }
        />
      </div>

      {/* Middle row */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        {/* Severity distribution */}
        <div className="p-4 rounded" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
          <SectionHeader>SEVERITY DISTRIBUTION</SectionHeader>
          <div className="space-y-2 mt-3">
            {[
              ['HIGH',        highCount, CONFIDENCE_COLORS.HIGH],
              ['MEDIUM',      medCount,  CONFIDENCE_COLORS.MEDIUM],
              ['LOW',         lowCount,  CONFIDENCE_COLORS.LOW],
              ['SPECULATIVE', specCount, CONFIDENCE_COLORS.SPECULATIVE],
            ].map(([label, count, color]) => (
              <div key={label} className="flex items-center gap-2 text-xs font-mono">
                <span className="w-20 shrink-0" style={{ color: 'var(--text-muted)' }}>{label}</span>
                <span className="w-6 text-right shrink-0" style={{ color }}>{count}</span>
                <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-raised)' }}>
                  <div className="h-full rounded-full"
                    style={{ width: `${(count / maxCount) * 100}%`, background: color }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Reports */}
        <div className="p-4 rounded" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
          <SectionHeader>REPORTS</SectionHeader>
          {reports.length > 0 ? (
            <div className="mt-3 space-y-1.5">
              {reports.slice(0, 5).map((r) => (
                <button
                  key={r.id}
                  onClick={() => setActiveTab('reports')}
                  className="w-full text-left flex items-center gap-3 text-xs font-mono px-1 py-1 rounded cursor-pointer transition-colors"
                  style={{ background: 'none', border: 'none' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-raised)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'none'}
                >
                  <span style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>{r.profile}</span>
                  <span className="font-mono text-[10px]" style={{ color: 'var(--text-muted)' }}>
                    {(r.id ?? '').slice(0, 8)}
                  </span>
                  {r.examiner && (
                    <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{r.examiner}</span>
                  )}
                  <span className="ml-auto text-[10px] shrink-0" style={{ color: 'var(--text-muted)' }}>
                    {r.created_at ? new Date(r.created_at).toLocaleDateString() : ''}
                  </span>
                </button>
              ))}
            </div>
          ) : (
            <p className="mt-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
              No reports generated yet · Generate one from the Reports tab
            </p>
          )}
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-2 gap-3">
        {/* Activity feed */}
        <div className="p-4 rounded" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
          <SectionHeader>RECENT ACTIVITY</SectionHeader>
          <ActivityFeed findings={findings} delta={delta} setActiveTab={setActiveTab} setSelectedFindingId={setSelectedFindingId} />
        </div>

        {/* MITRE ATT&CK */}
        <div className="p-4 rounded" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
          <SectionHeader>MITRE ATT&CK · {mitreIds.length} techniques</SectionHeader>
          {mitreIds.length > 0 ? (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {mitreIds.map((id) => (
                <span key={id} className="px-2 py-0.5 rounded font-mono text-[11px]"
                  style={{ background: 'var(--cyan-dim)', color: 'var(--cyan)', border: '1px solid var(--border-soft)' }}>
                  {id}
                </span>
              ))}
            </div>
          ) : (
            <p className="mt-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
              No MITRE technique IDs found in findings.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

function KPICard({ label, value, color, loading, extra, onClick }) {
  return (
    <div
      className={`px-4 py-3 rounded ${onClick ? 'cursor-pointer hover:bg-bg-raised transition-colors' : ''}`}
      style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter') onClick() } : undefined}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[11px] font-sans font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</span>
        {loading
          ? <Skeleton style={{ height: 20, width: 40 }} />
          : <span className="font-mono font-bold text-xl" style={{ color }}>{value}</span>}
      </div>
      {extra}
    </div>
  )
}

function SectionHeader({ children }) {
  return (
    <p className="text-[11px] font-sans font-semibold tracking-wider uppercase" style={{ color: 'var(--text-muted)' }}>
      {children}
    </p>
  )
}

const TIME_RANGES = [
  { label: 'Last hour', value: '1h', ms: 60 * 60 * 1000 },
  { label: 'Last 24h', value: '24h', ms: 24 * 60 * 60 * 1000 },
  { label: 'Last 7d', value: '7d', ms: 7 * 24 * 60 * 60 * 1000 },
  { label: 'Last 30d', value: '30d', ms: 30 * 24 * 60 * 60 * 1000 },
  { label: 'All', value: 'all', ms: Infinity },
]

function ActivityFeed({ findings, delta, setActiveTab, setSelectedFindingId }) {
  const [timeRange, setTimeRange] = useState('24h')

  const cutoff = TIME_RANGES.find((t) => t.value === timeRange)?.ms ?? Infinity

  const filtered = [...findings]
    .filter((f) => {
      if (cutoff === Infinity) return true
      const ts = f.modified_at || f.timestamp || f.event_timestamp
      if (!ts) return false
      return Date.now() - new Date(ts).getTime() < cutoff
    })
    .sort((a, b) => new Date(b.modified_at || b.timestamp || b.event_timestamp) - new Date(a.modified_at || a.timestamp || a.event_timestamp))
    .slice(0, 8)

  function handleClick(f) {
    setSelectedFindingId(f.id)
    setActiveTab('findings')
  }

  return (
    <>
      <div className="mt-3 mb-2 flex gap-1">
        {TIME_RANGES.map((t) => (
          <button
            key={t.value}
            onClick={() => setTimeRange(t.value)}
            className="px-2 py-0.5 rounded text-[10px] font-mono cursor-pointer transition-colors"
            style={{
              background: timeRange === t.value ? 'var(--cyan-dim)' : 'var(--bg-raised)',
              color: timeRange === t.value ? 'var(--cyan)' : 'var(--text-muted)',
              border: `1px solid ${timeRange === t.value ? 'var(--border-soft)' : 'var(--border-faint)'}`,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>No findings in this period.</p>
      ) : (
        <div className="space-y-1.5">
          {filtered.map((f) => {
            const color = CONFIDENCE_COLORS[(f.confidence ?? '').toUpperCase()] ?? 'var(--text-muted)'
            const staged = delta.find((d) => d.id === f.id)
            const activityTs = f.modified_at || f.timestamp || f.event_timestamp
            return (
              <button
                key={f.id}
                onClick={() => handleClick(f)}
                className="w-full text-left flex items-center gap-2 text-xs px-1 py-0.5 rounded cursor-pointer transition-colors"
                style={{ background: 'none', border: 'none' }}
                onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-raised)'}
                onMouseLeave={(e) => e.currentTarget.style.background = 'none'}
              >
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} />
                <span className="font-mono" style={{ color: 'var(--text-muted)', flexShrink: 0, whiteSpace: 'nowrap' }}>{f.id}</span>
                <span className="flex-1 truncate" style={{ color: 'var(--text-primary)' }}>{f.title}</span>
                {staged && (
                  <span className="font-mono text-[10px]" style={{ color: 'var(--status-staged)' }}>staged</span>
                )}
                {activityTs && (
                  <span className="font-mono text-[10px] shrink-0" style={{ color: 'var(--text-muted)' }}>
                    {formatDistanceToNow(new Date(activityTs), { addSuffix: true })}
                  </span>
                )}
              </button>
            )
          })}
        </div>
      )}
    </>
  )
}
