import { useState, useMemo, Fragment } from 'react'
import { useStoreSlice } from '../../store/useStore'
import { SkeletonBlock } from '../common/Skeleton'

const CONF_COLOR = {
  HIGH:        'var(--crimson)',
  MEDIUM:      'var(--amber)',
  LOW:         'var(--cyan)',
  SPECULATIVE: 'var(--violet)',
}

const displayHost = (h) => (h ? h.toUpperCase() : 'UNKNOWN');

function ConfidenceIcon({ confidence }) {
  const size = "w-3 h-3 inline-block mr-1 align-middle";
  if (confidence === 'HIGH') {
    return (
      <svg className={size} viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2L2 22h20L12 2z" />
      </svg>
    )
  }
  if (confidence === 'MEDIUM') {
    return (
      <svg className={size} viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2L2 12l10 10 10-10L12 2z" />
      </svg>
    )
  }
  if (confidence === 'LOW') {
    return (
      <svg className={size} viewBox="0 0 24 24" fill="currentColor">
        <circle cx="12" cy="12" r="10" />
      </svg>
    )
  }
  return (
    <svg className={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
      <path d="M12 2L2 12l10 10 10-10L12 2z" />
    </svg>
  )
}

const STATUS_COLOR = {
  DRAFT:    'var(--amber)',
  APPROVED: 'var(--jade)',
  REJECTED: 'var(--crimson)',
}

export function IocsTab() {
  const { iocs, findings, setActiveTab, setSelectedFindingId, isLoading } = useStoreSlice((state) => ({
    iocs: state.iocs,
    findings: state.findings,
    setActiveTab: state.setActiveTab,
    setSelectedFindingId: state.setSelectedFindingId,
    isLoading: state.isLoading,
  }))
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [expandedRows, setExpandedRows] = useState(new Set())

  const uniqueHosts = useMemo(() => {
    return [...new Set(findings.map((f) => f.host).filter(Boolean).map((h) => h.toUpperCase()))]
  }, [findings])
  const isSingleHost = uniqueHosts.length === 1
  const singleHostName = isSingleHost ? displayHost(uniqueHosts[0]) : null

  // Collect unique categories from data
  const categories = useMemo(() => {
    const cats = new Set()
    for (const ioc of iocs) {
      const cat = (ioc.category ?? '').trim()
      if (cat) cats.add(cat)
    }
    return [...cats].sort()
  }, [iocs])

  const filtered = useMemo(() => {
    let list = iocs
    if (categoryFilter !== 'all') {
      list = list.filter((ioc) => (ioc.category ?? '') === categoryFilter)
    }
    if (statusFilter !== 'all') {
      list = list.filter((ioc) => (ioc.status ?? '') === statusFilter)
    }
    if (search) {
      const q = search.toLowerCase()
      list = list.filter((ioc) =>
        (ioc.value ?? '').toLowerCase().includes(q) ||
        (ioc.id ?? '').toLowerCase().includes(q) ||
        (ioc.type ?? '').toLowerCase().includes(q)
      )
    }
    return list
  }, [iocs, categoryFilter, statusFilter, search])

  function toggleRow(id) {
    setExpandedRows((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function handleFindingClick(findingId) {
    if (!findingId) return
    setSelectedFindingId(findingId)
    setActiveTab('findings')
  }

  async function handleCopy(value) {
    try {
      await navigator.clipboard.writeText(value)
    } catch {
      // clipboard not available — silently ignore
    }
  }

  if (isLoading) {
    return (
      <div className="h-full overflow-y-auto p-5 space-y-4" style={{ background: 'var(--bg-base)' }}>
        <div className="pb-2 border-b" style={{ borderColor: 'var(--border-faint)' }}>
          <h1 className="font-display font-bold text-lg" style={{ color: 'var(--text-bright)' }}>IOCs</h1>
        </div>
        <SkeletonBlock rows={10} gap={12} />
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto p-5 space-y-4 flex flex-col" style={{ background: 'var(--bg-base)' }}>
      {/* Header + Filters */}
      <div className="shrink-0 space-y-3 pb-2 border-b" style={{ borderColor: 'var(--border-faint)' }}>
        <div className="flex justify-between items-center">
          <div className="flex items-baseline gap-2">
            <h1 className="font-display font-bold text-lg" style={{ color: 'var(--text-bright)' }}>
              Indicators of Compromise {isSingleHost && `— Host: ${singleHostName}`}
            </h1>
            <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
              ({filtered.length} of {iocs.length})
            </span>
          </div>
        </div>

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search */}
          <input
            type="text"
            placeholder="Search IOCs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="px-2.5 py-1.5 rounded text-xs font-mono bg-transparent border focus:outline-none w-48"
            style={{
              borderColor: 'var(--border-soft)',
              color: 'var(--text-primary)',
              background: 'var(--bg-surface)',
            }}
          />

          {/* Category filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-2 py-1.5 rounded text-[11px] font-mono bg-transparent border focus:outline-none"
            style={{ borderColor: 'var(--border-soft)', color: 'var(--text-primary)', background: 'var(--bg-surface)' }}
          >
            <option value="all">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>

          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2 py-1.5 rounded text-[11px] font-mono bg-transparent border focus:outline-none"
            style={{ borderColor: 'var(--border-soft)', color: 'var(--text-primary)', background: 'var(--bg-surface)' }}
          >
            <option value="all">All Status</option>
            <option value="DRAFT">DRAFT</option>
            <option value="APPROVED">APPROVED</option>
            <option value="REJECTED">REJECTED</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto min-h-0">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-12 h-12 mb-3 opacity-40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10" />
              <circle cx="12" cy="12" r="4" />
              <line x1="12" y1="2" x2="12" y2="6" />
              <line x1="12" y1="18" x2="12" y2="22" />
              <line x1="2" y1="12" x2="6" y2="12" />
              <line x1="18" y1="12" x2="22" y2="12" />
            </svg>
            <p className="font-mono text-sm">No IOCs match the current filters.</p>
          </div>
        ) : (
          <table className="w-full text-left text-xs" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr className="border-b sticky top-0" style={{ borderColor: 'var(--border-soft)', color: 'var(--text-muted)', background: 'var(--bg-base)' }}>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px] w-8"></th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Value</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Type</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Category</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Confidence</th>
                {!isSingleHost && <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Hosts</th>}
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Source Findings</th>
                <th className="py-2.5 font-sans font-semibold uppercase tracking-wider text-[10px]">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y" style={{ divideColor: 'var(--border-faint)' }}>
              {filtered.map((ioc) => {
                const isExpanded = expandedRows.has(ioc.id)
                const confColor = CONF_COLOR[ioc.confidence] ?? 'var(--text-muted)'
                const statusColor = STATUS_COLOR[ioc.status] ?? 'var(--text-muted)'
                const hosts = [...new Set((ioc.sightings ?? []).map((s) => s.host).filter(Boolean))]

                return (
                  <Fragment key={ioc.id}>
                    <tr className="group" style={{ color: 'var(--text-primary)' }}>
                      {/* Expand chevron */}
                      <td className="py-3 pr-4">
                        <button
                          onClick={() => toggleRow(ioc.id)}
                          className="text-text-muted hover:text-text-primary transition-colors"
                          title={isExpanded ? 'Collapse' : 'Expand'}
                        >
                          <svg
                            viewBox="0 0 12 12"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="1.5"
                            className={`w-3 h-3 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                          >
                            <path d="M4 2l4 4-4 4" />
                          </svg>
                        </button>
                      </td>

                      {/* Value + copy */}
                      <td className="py-3 pr-4">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-[11px] truncate max-w-[280px]" style={{ color: 'var(--text-bright)' }}>
                            {ioc.value}
                          </span>
                          <button
                            onClick={() => handleCopy(ioc.value)}
                            className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded hover:bg-bg-raised"
                            title="Copy to clipboard"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-3 h-3">
                              <rect x="5" y="5" width="8" height="8" rx="1" />
                              <path d="M3 9H2a1 1 0 01-1-1V3a1 1 0 011-1h5a1 1 0 011 1v1" />
                            </svg>
                          </button>
                        </div>
                      </td>

                      {/* Type */}
                      <td className="py-3 pr-4">
                        <Badge color="var(--text-muted)">{ioc.type}</Badge>
                      </td>

                      {/* Category */}
                      <td className="py-3 pr-4">
                        <span className="font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                          {ioc.category}
                        </span>
                      </td>

                      {/* Confidence */}
                      <td className="py-3 pr-4">
                        <Badge color={confColor}>
                          <ConfidenceIcon confidence={ioc.confidence} /> {ioc.confidence}
                        </Badge>
                      </td>

                      {/* Hosts */}
                      {!isSingleHost && (
                        <td className="py-3 pr-4">
                          <div className="flex flex-wrap gap-1 max-w-[160px]">
                            {hosts.map((h) => (
                              <span
                                key={h}
                                className="font-mono text-[10px] px-1 py-0.5 rounded"
                                style={{ color: 'var(--text-muted)', background: 'var(--bg-raised)' }}
                              >
                                {displayHost(h)}
                              </span>
                            ))}
                            {hosts.length === 0 && <span style={{ color: 'var(--text-ghost)' }}>—</span>}
                          </div>
                        </td>
                      )}

                      {/* Source Findings */}
                      <td className="py-3 pr-4">
                        <div className="flex flex-wrap gap-1">
                          {(ioc.source_findings ?? []).map((fid) => (
                            <button
                              key={fid}
                              onClick={(e) => { e.stopPropagation(); handleFindingClick(fid) }}
                              className="font-mono text-[11px] px-1 py-0.5 rounded cursor-pointer hover:underline"
                              style={{ color: 'var(--cyan)', background: 'var(--cyan-dim)' }}
                            >
                              {fid}
                            </button>
                          ))}
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3">
                        <Badge color={statusColor}>{ioc.status}</Badge>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-bg-surface">
                        <td colSpan={isSingleHost ? 7 : 8} className="p-4 border-b" style={{ borderColor: 'var(--border-faint)' }}>
                          <div className="space-y-2">
                            {/* MITRE techniques */}
                            {(ioc.mitre_techniques ?? []).length > 0 && (
                              <div className="flex items-start gap-2">
                                <span className="font-mono text-[10px] uppercase tracking-wider shrink-0 mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                  MITRE:
                                </span>
                                <div className="flex flex-wrap gap-1">
                                  {ioc.mitre_techniques.map((t) => {
                                    const isSub = t.includes('.')
                                    return (
                                      <span
                                        key={t}
                                        className="font-mono text-[10px] px-1.5 py-0.5 rounded"
                                        style={{
                                          color: 'var(--cyan)',
                                          background: 'var(--cyan-dim)',
                                          opacity: isSub ? 0.65 : 1,
                                          fontSize: isSub ? '9px' : '10px',
                                          marginLeft: isSub ? '4px' : '0px',
                                        }}
                                      >
                                        {t}
                                      </span>
                                    )
                                  })}
                                </div>
                              </div>
                            )}

                            {/* Tags */}
                            {(ioc.tags ?? []).length > 0 && (
                              <div className="flex items-start gap-2">
                                <span className="font-mono text-[10px] uppercase tracking-wider shrink-0 mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                  Tags:
                                </span>
                                <div className="flex flex-wrap gap-1">
                                  {ioc.tags.map((t) => (
                                    <span
                                      key={t}
                                      className="font-mono text-[10px] px-1.5 py-0.5 rounded"
                                      style={{ color: 'var(--amber)', background: 'var(--amber-dim)' }}
                                    >
                                      {t}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* ID footer */}
                            <div className="flex gap-4 text-[10px] font-mono" style={{ color: 'var(--text-ghost)' }}>
                              <span>ID: {ioc.id}</span>
                              {ioc.examiner && <span>Examiner: {ioc.examiner}</span>}
                              {ioc.created_at && <span>Created: {new Date(ioc.created_at).toISOString().replace('T', ' ').substring(0, 19)}</span>}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
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
