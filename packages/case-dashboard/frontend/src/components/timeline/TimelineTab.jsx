import { useState, useMemo } from 'react'
import { useStore } from '../../store/useStore'
import { formatDistanceToNow } from 'date-fns'
import { SkeletonBlock } from '../common/Skeleton'

const TYPE_COLOR = {
  auth:        'var(--amber)',
  execution:   'var(--crimson)',
  process:     'var(--crimson)',
  file:        'var(--cyan)',
  network:     'var(--violet)',
  persistence: 'var(--jade)',
  registry:    'var(--text-muted)',
  lateral:     'var(--crimson)',
  other:       'var(--text-ghost)',
}

const ALL_TYPES = ['auth','execution','process','file','network','persistence','registry','lateral','other']

const GAP_THRESHOLD_MS = 30 * 60 * 1000 // 30 min

export function TimelineTab() {
  const { timeline, findings, setSelectedFindingId, setActiveTab, isLoading } = useStore()
  const [typeFilter, setTypeFilter] = useState(new Set())
  const [hostFilter, setHostFilter] = useState('all')
  const [search, setSearch] = useState('')

  const hosts = useMemo(() => ['all', ...[...new Set(timeline.map((e) => e.host).filter(Boolean))]], [timeline])

  const filtered = useMemo(() => {
    let list = timeline
    if (typeFilter.size > 0) list = list.filter((e) => typeFilter.has(e.type))
    if (hostFilter !== 'all') list = list.filter((e) => e.host === hostFilter)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter((e) => e.description.toLowerCase().includes(q))
    }
    return [...list].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
  }, [timeline, typeFilter, hostFilter, search])

  function toggleType(t) {
    setTypeFilter((s) => { const n = new Set(s); n.has(t) ? n.delete(t) : n.add(t); return n })
  }

  function navigateToFinding(fid) {
    setSelectedFindingId(fid)
    setActiveTab('findings')
  }

  const loading = isLoading

  return (
    <div className="flex flex-col h-full overflow-hidden" style={{ background: 'var(--bg-base)' }}>
      {/* Filter bar */}
      <div className="shrink-0 flex items-center gap-3 px-4 py-2 border-b flex-wrap"
        style={{ borderColor: 'var(--border-faint)', background: 'var(--bg-surface)' }}>
        {/* Type filters */}
        <div className="flex gap-1 flex-wrap">
          {ALL_TYPES.map((t) => (
            <button key={t} onClick={() => toggleType(t)}
              className="px-2 py-0.5 rounded font-mono text-[10px] transition-colors capitalize"
              style={{
                background: typeFilter.has(t) ? TYPE_COLOR[t] + '22' : 'transparent',
                color: typeFilter.has(t) ? TYPE_COLOR[t] : 'var(--text-muted)',
                border: `1px solid ${typeFilter.has(t) ? TYPE_COLOR[t] : 'var(--border-soft)'}`,
              }}>
              {t}
            </button>
          ))}
        </div>

        {/* Host filter */}
        <select value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}
          className="px-2 py-0.5 rounded text-[11px] font-mono bg-transparent border focus:outline-none"
          style={{ borderColor: 'var(--border-soft)', color: 'var(--text-muted)' }}>
          {hosts.map((h) => <option key={h} value={h}>{h === 'all' ? 'all hosts' : h}</option>)}
        </select>

        {/* Search */}
        <input value={search} onChange={(e) => setSearch(e.target.value)}
          placeholder="Search events…" className="flex-1 min-w-[140px] px-2 py-0.5 rounded text-[11px] font-sans focus:outline-none"
          style={{ background: 'var(--bg-raised)', border: '1px solid var(--border-soft)', color: 'var(--text-primary)' }} />

        <span className="font-mono text-[10px] ml-auto shrink-0" style={{ color: 'var(--text-muted)' }}>
          {filtered.length} events
        </span>
      </div>

      {/* Event list */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-px">
        {loading ? (
          <SkeletonBlock rows={12} gap={10} />
        ) : filtered.length === 0 ? (
          <p className="text-xs font-mono mt-8 text-center" style={{ color: 'var(--text-muted)' }}>No events match filters.</p>
        ) : (
          filtered.map((ev, i) => {
            const color = TYPE_COLOR[ev.type] ?? 'var(--text-ghost)'
            const prev = filtered[i - 1]
            const gap = prev ? new Date(ev.timestamp).getTime() - new Date(prev.timestamp).getTime() : 0
            const showGap = gap > GAP_THRESHOLD_MS
            const showDateSep = i === 0 || new Date(ev.timestamp).toDateString() !== new Date(filtered[i-1].timestamp).toDateString()

            return (
              <div key={ev.id}>
                {showGap && (
                  <div className="flex items-center gap-2 my-1">
                    <div className="flex-1 h-px" style={{ background: 'var(--border-faint)' }} />
                    <span className="font-mono text-[10px] px-1.5 py-px rounded-full shrink-0"
                      style={{ color: 'var(--amber)', border: '1px solid var(--amber)', background: 'var(--amber-dim)' }}>
                      ▲ {Math.round(gap / 60000)}m gap
                    </span>
                    <div className="flex-1 h-px" style={{ background: 'var(--border-faint)' }} />
                  </div>
                )}
                {showDateSep && (
                  <div className="flex items-center gap-3 my-3">
                    <span className="font-mono text-[10px]" style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {new Date(ev.timestamp).toISOString().substring(0, 10)}
                      {ev.host && ` · ${ev.host}`}
                    </span>
                    <div className="flex-1 h-px" style={{ background: 'var(--border-faint)' }} />
                  </div>
                )}
                <div className="flex items-start gap-2 py-1 px-2 rounded transition-colors hover:bg-bg-raised group">
                  <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: color }} />
                  <span className="font-mono text-[11px] w-16 shrink-0" style={{ color: 'var(--text-muted)' }}>
                    {new Date(ev.timestamp).toISOString().substring(11, 19)}
                  </span>
                  <span className="font-mono text-[10px] w-16 shrink-0 capitalize" style={{ color }}>
                    [{ev.type}]
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-sans" style={{ color: 'var(--text-primary)' }}>
                      {ev.description}
                    </div>
                    {(ev.auto_created_from || (ev.related_findings && ev.related_findings.length > 0)) && (
                      <div className="mt-0.5 flex flex-wrap gap-x-2 text-[10px] font-mono">
                        {ev.auto_created_from && (
                          <span style={{ color: 'var(--text-muted)' }}>
                            auto-linked from{' '}
                            <a onClick={(e) => { e.preventDefault(); navigateToFinding(ev.auto_created_from) }}
                              className="text-cyan hover:underline cursor-pointer">
                              [{ev.auto_created_from}]
                            </a>
                          </span>
                        )}
                        {ev.related_findings && ev.related_findings.length > 0 && (
                          <span style={{ color: 'var(--text-muted)' }}>
                            related:{' '}
                            {ev.related_findings.map((fid) => (
                              <a key={fid} onClick={(e) => { e.preventDefault(); navigateToFinding(fid) }}
                                className="text-cyan hover:underline cursor-pointer mr-1">
                                [{fid}]
                              </a>
                            ))}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                  {/* Finding refs */}
                  {ev.finding_refs?.map((fid) => (
                    <a key={fid} onClick={(e) => { e.preventDefault(); navigateToFinding(fid) }}
                      className="font-mono text-[11px] text-cyan hover:underline cursor-pointer shrink-0 ml-1.5">
                      [{fid}]
                    </a>
                  ))}
                  {/* Approved badge */}
                  {ev.status === 'approved' && (
                    <span className="font-mono text-[9px] shrink-0" style={{ color: 'var(--jade)' }}>✓</span>
                  )}
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
