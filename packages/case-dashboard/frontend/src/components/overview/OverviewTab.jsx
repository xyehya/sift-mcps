import { useStore } from '../../store/useStore'
import { Skeleton } from '../common/Skeleton'
import { formatDistanceToNow } from 'date-fns'

const CONFIDENCE_COLORS = {
  HIGH:        'var(--crimson)',
  MEDIUM:      'var(--amber)',
  LOW:         'var(--cyan)',
  SPECULATIVE: 'var(--violet)',
}

export function OverviewTab() {
  const { activeCase, summary, findings, chainStatus, delta, isLoading, setActiveTab, setFindingsFilter, setCommitDrawerOpen } = useStore()

  // API shape: { findings: { total, by_status: {DRAFT, APPROVED, REJECTED} }, timeline, evidence, todos }
  const fstats    = summary?.findings ?? {}
  const byStatus  = fstats.by_status ?? {}
  const total     = fstats.total     ?? findings.length
  const approved  = byStatus.approved  ?? byStatus.APPROVED  ?? findings.filter((f) => f.status === 'approved' || f.status === 'APPROVED').length
  const pending   = byStatus.draft     ?? byStatus.DRAFT     ?? findings.filter((f) => f.status === 'draft'    || f.status === 'DRAFT').length
  const staged    = delta.length
  const reviewPct = findings.length > 0 ? Math.round((delta.length / findings.length) * 100) : 0

  const conf = (f) => (f.confidence ?? '').toUpperCase()
  const highCount = findings.filter((f) => conf(f) === 'HIGH').length
  const medCount  = findings.filter((f) => conf(f) === 'MEDIUM').length
  const lowCount  = findings.filter((f) => conf(f) === 'LOW').length
  const specCount = findings.filter((f) => conf(f) === 'SPECULATIVE').length
  const maxCount  = Math.max(highCount, medCount, lowCount, specCount, 1)

  // MITRE IDs from tags
  const mitreIds = [...new Set(
    findings.flatMap((f) => (f.tags ?? []).filter((t) => /^T\d{4}/.test(t)))
  )]

  const sealColor = !chainStatus
    ? 'var(--text-muted)'
    : chainStatus.sealed && chainStatus.hmac_verified
      ? 'var(--jade)'
      : chainStatus.sealed ? 'var(--amber)' : 'var(--crimson)'

  const sealLabel = !chainStatus ? '—'
    : chainStatus.sealed && chainStatus.hmac_verified ? 'SEALED ✓'
    : chainStatus.sealed ? 'SEALED · unverified'
    : 'UNSEALED'

  return (
    <div className="h-full overflow-y-auto p-5" style={{ background: 'var(--bg-base)' }}>
      {/* Case banner */}
      {activeCase && (
        <div className="mb-4 px-4 py-2.5 rounded flex items-center gap-3 text-xs font-mono"
          style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
          <span style={{ color: 'var(--text-muted)' }}>CASE</span>
          <span style={{ color: 'var(--text-bright)' }}>{activeCase.id}</span>
          {activeCase.title && (
            <>
              <span style={{ color: 'var(--border-hard)' }}>·</span>
              <span style={{ color: 'var(--text-primary)' }}>{activeCase.title}</span>
            </>
          )}
          <span className="ml-auto px-1.5 py-0.5 rounded text-[10px]"
            style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}>
            ACTIVE
          </span>
        </div>
      )}

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
          color="var(--amber)"
          loading={isLoading}
          onClick={() => staged > 0 && setCommitDrawerOpen(true)}
          extra={
            <div className="mt-2 h-1 rounded-full overflow-hidden" style={{ background: 'var(--bg-raised)' }}>
              <div className="h-full rounded-full transition-all"
                style={{ width: `${reviewPct}%`, background: 'var(--amber)' }} />
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

        {/* Evidence integrity */}
        <div className="p-4 rounded" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
          <SectionHeader>EVIDENCE INTEGRITY</SectionHeader>
          {chainStatus ? (
            <div className="mt-3 space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: sealColor }} />
                <span style={{ color: sealColor }}>{sealLabel}</span>
              </div>
              {chainStatus.write_blocked && (
                <div className="text-xs font-mono" style={{ color: 'var(--cyan)' }}>Write-protected</div>
              )}
              {chainStatus.total_entries != null && (
                <div className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                  {chainStatus.total_entries} evidence entries
                </div>
              )}
            </div>
          ) : (
            <div className="mt-3"><Skeleton style={{ width: '70%' }} /></div>
          )}
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-2 gap-3">
        {/* Activity feed */}
        <div className="p-4 rounded" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)' }}>
          <SectionHeader>RECENT ACTIVITY</SectionHeader>
          <ActivityFeed findings={findings} delta={delta} />
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
              No MITRE technique IDs found in finding tags.
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
      className={`p-4 rounded ${onClick ? 'cursor-pointer hover:ring-1 transition-shadow' : ''}`}
      style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-faint)', borderTop: `2px solid ${color}` }}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter') onClick() } : undefined}
    >
      <p className="text-[10px] font-sans font-semibold tracking-widest uppercase mb-1" style={{ color: 'var(--text-muted)' }}>{label}</p>
      {loading
        ? <Skeleton style={{ height: 36, width: 80 }} />
        : <p className="font-display font-bold text-4xl" style={{ color }}>{value}</p>}
      {extra}
    </div>
  )
}

function SectionHeader({ children }) {
  return (
    <p className="text-[10px] font-sans font-semibold tracking-widest uppercase" style={{ color: 'var(--text-muted)' }}>
      {children}
    </p>
  )
}

function ActivityFeed({ findings, delta }) {
  const recent = [...findings]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 8)

  if (recent.length === 0) {
    return <p className="mt-3 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>No findings yet.</p>
  }

  return (
    <div className="mt-3 space-y-1.5">
      {recent.map((f) => {
        const color = CONFIDENCE_COLORS[f.confidence] ?? 'var(--text-muted)'
        const staged = delta.find((d) => d.id === f.id)
        return (
          <div key={f.id} className="flex items-center gap-2 text-xs">
            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} />
            <span className="font-mono" style={{ color: 'var(--text-muted)', width: 44, shrink: 0 }}>{f.id}</span>
            <span className="flex-1 truncate" style={{ color: 'var(--text-primary)' }}>{f.title}</span>
            {staged && (
              <span className="font-mono text-[10px]" style={{ color: 'var(--amber)' }}>staged</span>
            )}
            {f.timestamp && (
              <span className="font-mono text-[10px] shrink-0" style={{ color: 'var(--text-muted)' }}>
                {formatDistanceToNow(new Date(f.timestamp), { addSuffix: true })}
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}
