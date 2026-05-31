import { useState, useMemo } from 'react'
import { useStore } from '../../store/useStore'
import { SkeletonBlock } from '../common/Skeleton'
import { createTodo, updateTodo, deleteTodo } from '../../api/endpoints'

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

const EMPTY_CREATE = { description: '', priority: 'medium', assignee: '', related: '' }

export function TodosTab() {
  const { todos, setTodos, summary, setActiveTab, setSelectedFindingId, isLoading, addToast, user } = useStore()
  const [priorityFilter, setPriorityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')

  const canWrite = user?.role === 'examiner'

  // Create form
  const [creating, setCreating] = useState(false)
  const [draft, setDraft] = useState(EMPTY_CREATE)
  const [savingNew, setSavingNew] = useState(false)

  // Inline edit
  const [editingId, setEditingId] = useState(null)
  const [editDraft, setEditDraft] = useState({ description: '', priority: 'medium' })
  // Per-row in-flight guard (toggle / delete / save)
  const [busyId, setBusyId] = useState(null)

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
      return new Date(iso).toLocaleString()
    } catch {
      return iso
    }
  }

  // --- CRUD handlers ---

  async function handleCreate() {
    const description = draft.description.trim()
    if (!description) {
      addToast('Description is required', 'error')
      return
    }
    const related = draft.related
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
    setSavingNew(true)
    try {
      const created = await createTodo({
        description,
        priority: draft.priority,
        assignee: draft.assignee.trim(),
        related_findings: related,
      })
      if (created) {
        setTodos([...todos, created])
        addToast(`Created ${created.todo_id}`, 'success')
        setDraft(EMPTY_CREATE)
        setCreating(false)
      }
    } catch (ex) {
      addToast(ex.message, 'error')
    } finally {
      setSavingNew(false)
    }
  }

  async function handleToggleStatus(todo) {
    const next = (todo.status ?? 'open') === 'completed' ? 'open' : 'completed'
    setBusyId(todo.todo_id)
    try {
      const updated = await updateTodo(todo.todo_id, { status: next })
      if (updated) {
        setTodos(todos.map((t) => (t.todo_id === todo.todo_id ? updated : t)))
        addToast(`${todo.todo_id} marked ${next}`, next === 'completed' ? 'success' : 'info')
      }
    } catch (ex) {
      addToast(ex.message, 'error')
    } finally {
      setBusyId(null)
    }
  }

  function startEdit(todo) {
    setEditingId(todo.todo_id)
    setEditDraft({ description: todo.description ?? '', priority: todo.priority ?? 'medium' })
  }

  function cancelEdit() {
    setEditingId(null)
  }

  async function handleSaveEdit(todo) {
    const description = editDraft.description.trim()
    if (!description) {
      addToast('Description cannot be empty', 'error')
      return
    }
    setBusyId(todo.todo_id)
    try {
      const updated = await updateTodo(todo.todo_id, {
        description,
        priority: editDraft.priority,
      })
      if (updated) {
        setTodos(todos.map((t) => (t.todo_id === todo.todo_id ? updated : t)))
        addToast(`Updated ${todo.todo_id}`, 'success')
        setEditingId(null)
      }
    } catch (ex) {
      addToast(ex.message, 'error')
    } finally {
      setBusyId(null)
    }
  }

  async function handleDelete(todo) {
    if (!window.confirm(`Delete ${todo.todo_id}? This cannot be undone.`)) return
    setBusyId(todo.todo_id)
    try {
      await deleteTodo(todo.todo_id)
      setTodos(todos.filter((t) => t.todo_id !== todo.todo_id))
      addToast(`Deleted ${todo.todo_id}`, 'info')
    } catch (ex) {
      addToast(ex.message, 'error')
    } finally {
      setBusyId(null)
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

  const inputStyle = {
    borderColor: 'var(--border-soft)',
    color: 'var(--text-primary)',
    background: 'var(--bg-surface)',
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

        {/* Filter bar + New */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="px-2 py-1.5 rounded text-[11px] font-mono bg-transparent border focus:outline-none"
            style={inputStyle}
          >
            <option value="all">All Priorities</option>
            <option value="high">▲ High</option>
            <option value="medium">◆ Medium</option>
            <option value="low">● Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2 py-1.5 rounded text-[11px] font-mono bg-transparent border focus:outline-none"
            style={inputStyle}
          >
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="completed">Completed</option>
          </select>

          {canWrite && (
            <button
              onClick={() => setCreating((v) => !v)}
              className="ml-auto px-3 py-1.5 rounded text-[11px] font-mono font-semibold cursor-pointer transition-colors"
              style={{
                background: creating ? 'var(--bg-raised)' : 'var(--cyan-dim)',
                color: 'var(--cyan)',
                border: '1px solid var(--border-soft)',
              }}
            >
              {creating ? 'Cancel' : '+ New TODO'}
            </button>
          )}
        </div>

        {/* Create form */}
        {canWrite && creating && (
          <div className="rounded border p-3 space-y-2" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-soft)' }}>
            <textarea
              autoFocus
              value={draft.description}
              onChange={(e) => setDraft({ ...draft, description: e.target.value })}
              placeholder="Describe the task…"
              rows={2}
              className="w-full px-2 py-1.5 rounded text-xs font-sans border focus:outline-none resize-y"
              style={inputStyle}
            />
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={draft.priority}
                onChange={(e) => setDraft({ ...draft, priority: e.target.value })}
                className="px-2 py-1.5 rounded text-[11px] font-mono border focus:outline-none"
                style={inputStyle}
              >
                <option value="high">▲ High</option>
                <option value="medium">◆ Medium</option>
                <option value="low">● Low</option>
              </select>
              <input
                value={draft.assignee}
                onChange={(e) => setDraft({ ...draft, assignee: e.target.value })}
                placeholder="Assignee (optional)"
                className="px-2 py-1.5 rounded text-[11px] font-mono border focus:outline-none"
                style={inputStyle}
              />
              <input
                value={draft.related}
                onChange={(e) => setDraft({ ...draft, related: e.target.value })}
                placeholder="Related findings, comma-separated (optional)"
                className="flex-1 min-w-[16rem] px-2 py-1.5 rounded text-[11px] font-mono border focus:outline-none"
                style={inputStyle}
              />
              <button
                onClick={handleCreate}
                disabled={savingNew}
                className="px-3 py-1.5 rounded text-[11px] font-mono font-semibold cursor-pointer transition-opacity disabled:opacity-50"
                style={{ background: 'var(--jade-dim)', color: 'var(--jade)', border: '1px solid var(--jade)' }}
              >
                {savingNew ? 'Saving…' : 'Create'}
              </button>
            </div>
          </div>
        )}
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
            <p className="text-xs text-text-muted mt-1 max-w-xs">
              {canWrite ? 'Create one with “+ New TODO”, or they appear once the agent registers them.' : 'Tasks will appear once the agent or examiner registers them.'}
            </p>
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
                <th className="py-2.5 pr-4 font-sans font-semibold uppercase tracking-wider text-[10px]">Created</th>
                {canWrite && <th className="py-2.5 font-sans font-semibold uppercase tracking-wider text-[10px] text-right">Actions</th>}
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
                const isEditing = editingId === todo.todo_id
                const isBusy = busyId === todo.todo_id

                return (
                  <tr key={todo.todo_id} className="group" style={{ color: 'var(--text-primary)', opacity: isBusy ? 0.6 : 1 }}>
                    {/* ID */}
                    <td className="py-3 pr-4 align-top">
                      <span className="font-mono text-[11px] whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {todo.todo_id}
                      </span>
                    </td>
                    {/* Title (description) */}
                    <td className="py-3 pr-4 align-top">
                      {isEditing ? (
                        <textarea
                          autoFocus
                          value={editDraft.description}
                          onChange={(e) => setEditDraft({ ...editDraft, description: e.target.value })}
                          rows={2}
                          className="w-full min-w-[14rem] px-2 py-1 rounded text-xs font-sans border focus:outline-none resize-y"
                          style={inputStyle}
                        />
                      ) : (
                        <div className="max-w-xs truncate font-sans text-xs" title={todo.description}>
                          {todo.description || '—'}
                        </div>
                      )}
                    </td>
                    {/* Priority */}
                    <td className="py-3 pr-4 align-top">
                      {isEditing ? (
                        <select
                          value={editDraft.priority}
                          onChange={(e) => setEditDraft({ ...editDraft, priority: e.target.value })}
                          className="px-2 py-1 rounded text-[11px] font-mono border focus:outline-none"
                          style={inputStyle}
                        >
                          <option value="high">▲ High</option>
                          <option value="medium">◆ Medium</option>
                          <option value="low">● Low</option>
                        </select>
                      ) : (
                        <span
                          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold"
                          style={{ color: priColor, background: priColor + '18' }}
                        >
                          <span>{priShape}</span>
                          <span>{pri}</span>
                        </span>
                      )}
                    </td>
                    {/* Examiner */}
                    <td className="py-3 pr-4 align-top">
                      <span className="font-sans text-[11px]" style={{ color: 'var(--text-muted)' }}>
                        {todo.examiner || todo.created_by || '—'}
                      </span>
                    </td>
                    {/* Status */}
                    <td className="py-3 pr-4 align-top">
                      <span
                        className="inline-flex px-1.5 py-0.5 rounded font-mono text-[10px] font-semibold"
                        style={{ color: statusColor, background: statusColor + '18' }}
                      >
                        {stat.toUpperCase()}
                      </span>
                    </td>
                    {/* Related findings */}
                    <td className="py-3 pr-4 align-top">
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
                    <td className="py-3 pr-4 align-top">
                      <span className="font-mono text-[11px] whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {formatDate(todo.created_at)}
                      </span>
                    </td>
                    {/* Actions */}
                    {canWrite && (
                      <td className="py-3 align-top">
                        <div className="flex items-center justify-end gap-1.5">
                          {isEditing ? (
                            <>
                              <ActionButton onClick={() => handleSaveEdit(todo)} disabled={isBusy} color="var(--jade)">Save</ActionButton>
                              <ActionButton onClick={cancelEdit} disabled={isBusy} color="var(--text-muted)">Cancel</ActionButton>
                            </>
                          ) : (
                            <>
                              <ActionButton onClick={() => handleToggleStatus(todo)} disabled={isBusy} color={stat === 'completed' ? 'var(--amber)' : 'var(--jade)'}>
                                {stat === 'completed' ? 'Reopen' : 'Complete'}
                              </ActionButton>
                              <ActionButton onClick={() => startEdit(todo)} disabled={isBusy} color="var(--cyan)">Edit</ActionButton>
                              <ActionButton onClick={() => handleDelete(todo)} disabled={isBusy} color="var(--crimson)">Delete</ActionButton>
                            </>
                          )}
                        </div>
                      </td>
                    )}
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

function ActionButton({ onClick, disabled, color, children }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="px-2 py-1 rounded font-mono text-[10px] font-semibold cursor-pointer transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      style={{ color, background: color + '14', border: `1px solid ${color}33` }}
    >
      {children}
    </button>
  )
}
