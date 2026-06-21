import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { ListTodo, Plus } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants } from '@/lib/motion'
import { SkeletonBlock } from '@/components/common/Skeleton'
import { sortTodos } from './todos-utils'
import { useTodos } from './useTodos'
import { TodoCreateForm } from './TodoCreateForm'
import { TodoRow } from './TodoRow'

// ─────────────────────────────────────────────────────────────────────────
// TodosTab — case task list (Mission-Control reskin of the legacy 489-line
// view, full functional parity). ONE primary scroll owner. Header + open/done
// counts → filter bar (priority · status · New) → examiner-only create form →
// table of TodoRows (inline edit · status toggle · delete · related-finding
// navigation). RBAC: write actions are examiner-only (canWrite). Empty states
// for no-todos and no-filter-match; loading skeleton.
//
// Decomposed into <=400-line files: todos-utils (sort/filter + token-class
// maps) · useTodos (CRUD + drafts + busy guard) · TodoCreateForm · TodoRow.
// Mock/real split is at the API adapter layer — no isMock here (§3).
// ─────────────────────────────────────────────────────────────────────────

const SELECT =
  'mono rounded-lg border border-border-soft bg-transparent px-2 py-1.5 text-[11px] text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

const TH = 'mono py-2.5 pr-4 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground'

export function TodosTab() {
  const variants = useMotionVariants()
  const { todos, setTodos, summary, setActiveTab, setSelectedFindingId, isLoading, addToast, user } =
    useStoreSlice((state) => ({
      todos: state.todos,
      setTodos: state.setTodos,
      summary: state.summary,
      setActiveTab: state.setActiveTab,
      setSelectedFindingId: state.setSelectedFindingId,
      isLoading: state.isLoading,
      addToast: state.addToast,
      user: state.user,
    }))

  const [priorityFilter, setPriorityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const canWrite = user?.role === 'examiner'

  const t = useTodos({ todos, setTodos, addToast })

  const sortedTodos = useMemo(
    () => sortTodos(todos, priorityFilter, statusFilter),
    [todos, priorityFilter, statusFilter],
  )

  function handleFindingClick(findingId) {
    if (!findingId) return
    setSelectedFindingId(findingId)
    setActiveTab('findings')
  }

  const openCount = summary?.todos?.open ?? todos.filter((x) => x.status === 'open').length
  const completedCount = summary?.todos?.completed ?? todos.filter((x) => x.status === 'completed').length

  if (isLoading) {
    return (
      <div className="h-full space-y-4 overflow-y-auto bg-bg-base p-5">
        <div className="border-b border-border-faint pb-2">
          <h1 className="font-display text-lg font-bold text-foreground">TODOs</h1>
        </div>
        <SkeletonBlock rows={10} gap={12} />
      </div>
    )
  }

  return (
    <motion.div
      variants={variants.fadeRise}
      initial="hidden"
      animate="show"
      className="flex h-full flex-col space-y-4 overflow-y-auto bg-bg-base p-5"
    >
      <div className="shrink-0 space-y-3 border-b border-border-faint pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-baseline gap-2">
            <h1 className="font-display text-lg font-bold text-foreground">TODOs</h1>
            <span className="mono text-xs text-muted-foreground">
              ({sortedTodos.length} of {todos.length})
            </span>
          </div>
          <div className="mono flex items-center gap-3 text-[11px]">
            <span className="text-status-pending">{openCount} open</span>
            <span className="text-status-approved">{completedCount} completed</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select aria-label="Filter by priority" value={priorityFilter} onChange={(e) => setPriorityFilter(e.target.value)} className={SELECT}>
            <option value="all">All Priorities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select aria-label="Filter by status" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={SELECT}>
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="completed">Completed</option>
          </select>

          {canWrite && (
            <button
              type="button"
              onClick={() => t.setCreating((v) => !v)}
              className={`mono ml-auto flex items-center gap-1 rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                t.creating
                  ? 'border-border-soft bg-bg-raised text-muted-foreground'
                  : 'border-primary bg-primary/10 text-primary'
              }`}
            >
              {t.creating ? 'Cancel' : (<><Plus className="size-3.5" aria-hidden />New TODO</>)}
            </button>
          )}
        </div>

        {canWrite && t.creating && (
          <TodoCreateForm draft={t.draft} onDraft={t.setDraft} saving={t.savingNew} onCreate={t.handleCreate} />
        )}
      </div>

      <div className="overflow-x-auto rounded-lg border border-border-soft bg-card p-4">
        {todos.length === 0 ? (
          <EmptyState
            title="No TODOs created for this case."
            subtitle={
              canWrite
                ? 'Create one with "New TODO", or they appear once the agent registers them.'
                : 'Tasks will appear once the agent or examiner registers them.'
            }
          />
        ) : sortedTodos.length === 0 ? (
          <EmptyState
            title="No TODOs match the current filters."
            subtitle="Try resetting the priority or status filters."
          />
        ) : (
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="sticky top-0 border-b border-border-soft bg-bg-base">
                <th className={TH}>ID</th>
                <th className={TH}>Title</th>
                <th className={TH}>Priority</th>
                <th className={TH}>Examiner</th>
                <th className={TH}>Status</th>
                <th className={TH}>Related Findings</th>
                <th className={TH}>Created</th>
                {canWrite && <th className={`${TH} text-right`}>Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-faint">
              {sortedTodos.map((todo) => (
                <TodoRow
                  key={todo.todo_id}
                  todo={todo}
                  canWrite={canWrite}
                  isEditing={t.editingId === todo.todo_id}
                  isBusy={t.busyId === todo.todo_id}
                  editDraft={t.editDraft}
                  onEditDraft={t.setEditDraft}
                  onFindingClick={handleFindingClick}
                  onToggleStatus={t.handleToggleStatus}
                  onStartEdit={t.startEdit}
                  onSaveEdit={t.handleSaveEdit}
                  onCancelEdit={t.cancelEdit}
                  onDelete={t.handleDelete}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </motion.div>
  )
}

function EmptyState({ title, subtitle }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center text-muted-foreground">
      <ListTodo className="mb-3 size-12 opacity-40" aria-hidden />
      <p className="mono text-sm">{title}</p>
      <p className="mt-1 max-w-xs text-xs text-muted-foreground">{subtitle}</p>
    </div>
  )
}
