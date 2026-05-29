import { useState, useMemo } from 'react'
import { useStore } from '../../store/useStore'
import { SkeletonBlock } from '../common/Skeleton'

const PRIORITY_WEIGHT = { high: 3, medium: 2, low: 1 }

const PRIORITY_COLOR = {
  high:   'var(--crimson)',
  medium: 'var(--amber)',
  low:    'var(--cyan)',
}

const PRIORITY_SHAPE = { high: '▲', medium: '◆', low: '●' }

const STATUS_COLOR = {
  open:      'var(--amber)',
  completed: 'var(--jade)',
}

export function TodosTab() {
  const { todos, summary, setActiveTab, setSelectedFindingId, isLoading } = useStore()
  const [priorityFilter, setPriorityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')

  const sortedTodos = useMemo(() => {
    let list = [...todos]
    if (priorityFilter !== 'all') {
      list = list.filter((t) => (t.priority ?? 'medium') === priorityFilter)
    }
    if (statusFilter !== 'all') {
      list = list.filter((t) => (t.status ?? 'open') === statusFilter)
    }
    // Default sort: priority desc (high → medium → low), then created_at asc
    list.sort((a, b) => {
      const pa = PRIORITY_WEIGHT[a.priority] ?? 2
      const pb = PRIORITY_WEIGHT[b.priority] ?? 2
      if (pa !== pb) return pb - pa
      return (a.created_at ?? '').localeCompare(b.created_at ?? '')
    })
    return list
  }, [todos, priorityFilter, statusFilter])

  function handleFindingClick(findingId) {
    if (!findingId) return
    setSelectedFindingId(findingId)
    setActiveTab('findings')
  }

  function formatDate(iso) {
    if (!iso) return '—'
    try {
      const d = new Date(iso)
      return d.toLocaleString()
    } catch {
      return iso
    }
  }

  const openCount = summary?.todos?.open ?? todos.filter((t) => t.status === 'open').length
  const completedCount = summary?.todos?.completed ?? todos.filter((t) => t.status === 'completed').length

  if (isLoading) {
    return (
      <div className="h-full overflow-y-auto p-5 space-y-4" style={{ background: 'var(--bg-base)' }}>
        <div className="pb-2 border-b" style={{ borderColor: 'var(--border-faint)' }}>
          <h1 className="font-display font-bold text-lg" style={{ color: 'var(--text-bright)' }}>TODOs</h1>
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
            <h1 className="font-display font-bold text-lg" style={{ color: 'var(--text-bright)' }}>TODOs</h1>
            <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
              ({sortedTodos.length} of {todos.length})
            </span>
          </div>
          <div className="flex items-center gap-3 font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
            <span style={{ color: 'var(--amber)' }}>{openCount} open</span>
            <span style={{ color: 'var(--jade)' }}>{completedCount} completed</span>
          </div>
        </div>

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Priority filter */}
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="px-2 py-1.5 rounded text-[11px] font-mono bg-transparent border focus:outline-none"
            style={{ borderColor: 'var(--border-soft)', color: 'var(--text-primary)', background: 'var(--bg-surface)' }}
          >
            <option value="all">All Priorities</option>
            <option value="high">▲ High</option>
            <option value="medium">◆ Medium</option>
            <option value="low">● Low</option>
          </select>

          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2 py-1.5 rounded text-[11px] font-mono bg-transparent border focus:outline-none"
            style={{ borderColor: 'var(--border-soft)', color: 'var(--text-primary)', background: 'var(--bg-surface)' }}
          >
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="completed">Completed</option>
          </select>
        </div>
      </div>

      {/* Table Container Card */}
      <div className="rounded border bg-bg-surface border-border-soft p-4 overflow-x-auto">
        {todos.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-12 h-12 mb-3 opacity-40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="4" width="18" height="16" rx="2" />
              <line x1="8" y1="9" x2="16" y2="9" />
              <line x1="8" y1="13" x2="16" y2="13" />
              <line x1="8" y1="17" x2="12" y2="17" />
            </svg>
            <p className="font-mono text-sm">No TODOs created for this case.</p>
            <p className="text-xs text-text-muted mt-1 max-w-xs">Tasks will appear once the agent or examiner registers them.</p>
          </div>
        ) : sortedTodos.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-12 h-12 mb-3 opacity-40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="4" width="18" height="16" rx="2" />
              <line x1="8" y1="9" x2="16" y2="9" />
              <line x1="8" y1="13" x2="16" y2="13" />
              <line x1="8" y1="17" x2="12" y2="17" />
            </svg>
            <p className="font-mono text-sm">No TODOs match the current filters.</p>
            <p className="text-xs text-text-muted mt-1 max-w-xs">Try resetting the priority or status filters.</p>
          </div>
        ) : (
          <table className="w-full text-left text-xs" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr className="border-b sticky top-0" style={{ borderColor: 'var(--border-soft)', color: 'var(--text-muted)', background: 'var(--bg-base)' }}>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">ID</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Title</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Priority</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Examiner</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Status</th>
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Related Findings</th>
                <th className="py-2.5 font-sans font-semibold uppercase tracking-wider text-[10px]">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y" style={{ divideColor: 'var(--border-faint)' }}>
              {sortedTodos.map((todo) => {
                const pri = (todo.priority ?? 'medium').toLowerCase()
                const priColor = PRIORITY_COLOR[pri] ?? 'var(--text-muted)'
                const priShape = PRIORITY_SHAPE[pri] ?? '●'
                const stat = todo.status ?? 'open'
                const statusColor = STATUS_COLOR[stat] ?? 'var(--text-muted)'
                const relatedFids = todo.related_findings ?? []

                return (
                  <tr key={todo.todo_id} className="group" style={{ color: 'var(--text-primary)' }}>
                    {/* ID */}
                    <td className="py-3 pr-4">
                      <span className="font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                        {todo.todo_id}
                      </span>
                    </td>
                    {/* Title (description) */}
                    <td className="py-3 pr-4">
                      <div className="max-w-xs truncate font-sans text-xs" title={todo.description}>
                        {todo.description || '—'}
                      </div>
                    </td>
                    {/* Priority — shape-disambiguated badge */}
                    <td className="py-3 pr-4">
                      <span
                        className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold"
                        style={{ color: priColor, background: priColor + '18' }}
                      >
                        <span>{priShape}</span>
                        <span>{pri}</span>
                      </span>
                    </td>
                    {/* Examiner */}
                    <td className="py-3 pr-4">
                      <span className="font-sans text-[11px]" style={{ color: 'var(--text-muted)' }}>
                        {todo.examiner || todo.created_by || '—'}
                      </span>
                    </td>
                    {/* Status */}
                    <td className="py-3 pr-4">
                      <span
                        className="inline-flex px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold"
                        style={{ color: statusColor, background: statusColor + '18' }}
                      >
                        {stat.toUpperCase()}
                      </span>
                    </td>
                    {/* Related findings — clickable links */}
                    <td className="py-3 pr-4">
                      {relatedFids.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {relatedFids.map((fid) => (
                            <button
                              key={fid}
                              onClick={() => handleFindingClick(fid)}
                              className="font-mono text-[11px] underline underline-offset-2 decoration-1 hover:opacity-80 transition-opacity"
                              style={{ color: 'var(--cyan)' }}
                              title={`Go to ${fid}`}
                            >
                              {fid}
                            </button>
                          ))}
                        </div>
                      ) : (
                        <span className="font-mono text-[11px]" style={{ color: 'var(--text-ghost)' }}>—</span>
                      )}
                    </td>
                    {/* Created at */}
                    <td className="py-3">
                      <span className="font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                        {formatDate(todo.created_at)}
                      </span>
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
