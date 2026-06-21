import { Triangle, Diamond, Circle } from 'lucide-react'

import { priorityChipClass, statusChipClass, formatDate } from './todos-utils'

// ─────────────────────────────────────────────────────────────────────────
// TodoRow — one table row (legacy parity): ID · title (inline-editable) ·
// priority chip (severity colour) · examiner · status chip · related-finding
// links (navigate to Findings) · created date · row actions (complete/reopen ·
// edit · delete, or save/cancel while editing). Examiner-only actions are
// gated by `canWrite` upstream. Reskinned to token classes + lucide priority
// icons; the in-flight row dims via opacity (data-driven, not a hex).
// ─────────────────────────────────────────────────────────────────────────

const SELECT =
  'mono rounded-lg border border-border-soft bg-bg-raised px-2 py-1 text-[11px] text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

/** Module-scope priority shape icon — explicit literal branches so the JIT and
 *  the react-hooks/static-components rule both see fixed component references. */
function PriorityIcon({ priority, className }) {
  if (priority === 'high') return <Triangle className={className} aria-hidden />
  if (priority === 'low') return <Circle className={className} aria-hidden />
  return <Diamond className={className} aria-hidden />
}

function ActionButton({ onClick, disabled, tone, children }) {
  // tone ∈ jade|amber|orange|crimson|muted — literal class maps (JIT-safe).
  const TONE = {
    jade: 'text-status-approved border-jade/30 bg-jade/10',
    amber: 'text-status-pending border-amber/30 bg-amber/10',
    orange: 'text-primary border-primary/30 bg-primary/10',
    crimson: 'text-destructive border-crimson/30 bg-crimson/10',
    muted: 'text-muted-foreground border-border-soft bg-bg-raised',
  }
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`mono rounded border px-2 py-1 text-[10px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 ${TONE[tone] || TONE.muted}`}
    >
      {children}
    </button>
  )
}

export function TodoRow({
  todo,
  canWrite,
  isEditing,
  isBusy,
  editDraft,
  onEditDraft,
  onFindingClick,
  onToggleStatus,
  onStartEdit,
  onSaveEdit,
  onCancelEdit,
  onDelete,
}) {
  const pri = (todo.priority ?? 'medium').toLowerCase()
  const stat = todo.status ?? 'open'
  const relatedFids = todo.related_findings ?? []

  return (
    <tr className={`group align-top text-text-primary ${isBusy ? 'opacity-60' : ''}`}>
      <td className="py-3 pr-4">
        <span className="mono whitespace-nowrap text-[11px] text-muted-foreground">{todo.todo_id}</span>
      </td>

      <td className="py-3 pr-4">
        {isEditing ? (
          <textarea
            autoFocus
            aria-label="Edit description"
            value={editDraft.description}
            onChange={(e) => onEditDraft({ ...editDraft, description: e.target.value })}
            rows={2}
            className="w-full min-w-[14rem] resize-y rounded-lg border border-border-soft bg-bg-raised px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          />
        ) : (
          <div className="max-w-xs truncate text-xs" title={todo.description}>
            {todo.description || '—'}
          </div>
        )}
      </td>

      <td className="py-3 pr-4">
        {isEditing ? (
          <select
            aria-label="Edit priority"
            value={editDraft.priority}
            onChange={(e) => onEditDraft({ ...editDraft, priority: e.target.value })}
            className={SELECT}
          >
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        ) : (
          <span
            className={`mono inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold ${priorityChipClass(pri)}`}
          >
            <PriorityIcon priority={pri} className="size-2.5" />
            <span>{pri}</span>
          </span>
        )}
      </td>

      <td className="py-3 pr-4">
        <span className="text-[11px] text-muted-foreground">{todo.examiner || todo.created_by || '—'}</span>
      </td>

      <td className="py-3 pr-4">
        <span className={`mono inline-flex rounded border px-1.5 py-0.5 text-[10px] font-semibold ${statusChipClass(stat)}`}>
          {stat.toUpperCase()}
        </span>
      </td>

      <td className="py-3 pr-4">
        {relatedFids.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {relatedFids.map((fid) => (
              <button
                key={fid}
                type="button"
                onClick={() => onFindingClick(fid)}
                className="mono text-[11px] text-primary underline decoration-1 underline-offset-2 transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                title={`Go to ${fid}`}
              >
                {fid}
              </button>
            ))}
          </div>
        ) : (
          <span className="mono text-[11px] text-text-ghost">—</span>
        )}
      </td>

      <td className="py-3 pr-4">
        <span className="mono whitespace-nowrap text-[11px] text-muted-foreground">{formatDate(todo.created_at)}</span>
      </td>

      {canWrite && (
        <td className="py-3">
          <div className="flex items-center justify-end gap-1.5">
            {isEditing ? (
              <>
                <ActionButton onClick={() => onSaveEdit(todo)} disabled={isBusy} tone="jade">
                  Save
                </ActionButton>
                <ActionButton onClick={onCancelEdit} disabled={isBusy} tone="muted">
                  Cancel
                </ActionButton>
              </>
            ) : (
              <>
                <ActionButton
                  onClick={() => onToggleStatus(todo)}
                  disabled={isBusy}
                  tone={stat === 'completed' ? 'amber' : 'jade'}
                >
                  {stat === 'completed' ? 'Reopen' : 'Complete'}
                </ActionButton>
                <ActionButton onClick={() => onStartEdit(todo)} disabled={isBusy} tone="orange">
                  Edit
                </ActionButton>
                <ActionButton onClick={() => onDelete(todo)} disabled={isBusy} tone="crimson">
                  Delete
                </ActionButton>
              </>
            )}
          </div>
        </td>
      )}
    </tr>
  )
}
