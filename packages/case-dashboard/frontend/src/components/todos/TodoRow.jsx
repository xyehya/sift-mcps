import { Check, MoreHorizontal, Pencil, RotateCcw, Trash2, X } from 'lucide-react'

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  priorityChipClass,
  priorityLabel,
  statusChipClass,
  formatDate,
} from './todos-utils'

// ─────────────────────────────────────────────────────────────────────────
// TodoRow — one table row (legacy parity): ID · title (inline-editable) ·
// severity chip (token colour + Title-case text label, NO shape glyph) ·
// examiner · status chip · related-finding links (navigate to Findings) ·
// created date · ONE row affordance (single-click status toggle as the primary
// action + a "⋯" overflow menu holding edit / delete). Examiner-only actions
// are gated by `canWrite` upstream. Severity rides typography + token colour,
// not ornament (contract B2/B5); the in-flight row dims via opacity.
// ─────────────────────────────────────────────────────────────────────────

const SELECT =
  'mono rounded-lg border border-border-soft bg-bg-raised px-2 py-1 text-[11px] text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

/** Compact icon affordance with a Tooltip + aria-label (contract B9). */
function IconAction({ label, onClick, disabled, tone, children }) {
  // tone ∈ jade|muted — literal class maps (JIT-safe).
  const TONE = {
    jade: 'text-status-approved border-jade/30 bg-jade/10 hover:bg-jade/20',
    muted: 'text-muted-foreground border-border-soft bg-bg-raised hover:text-foreground',
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={label}
          onClick={onClick}
          disabled={disabled}
          className={`mono inline-flex size-7 items-center justify-center rounded-md border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 ${TONE[tone] || TONE.muted}`}
        >
          {children}
        </button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
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
  const completed = stat === 'completed'
  const relatedFids = todo.related_findings ?? []

  return (
    <tr className={`group align-top text-foreground transition-colors hover:bg-secondary/50 ${isBusy ? 'opacity-60' : ''}`}>
      <td className="px-3 py-3">
        <span className="mono whitespace-nowrap text-[11px] tabular-nums text-muted-foreground">{todo.todo_id}</span>
      </td>

      <td className="px-3 py-3">
        {isEditing ? (
          <textarea
            autoFocus
            aria-label="Edit description"
            value={editDraft.description}
            onChange={(e) => onEditDraft({ ...editDraft, description: e.target.value })}
            rows={2}
            className="w-full min-w-[14rem] resize-y rounded-lg border border-border-soft bg-bg-raised px-2 py-1 text-[13px] text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          />
        ) : (
          <div className="max-w-xs truncate text-[13px] font-medium" title={todo.description}>
            {todo.description || '—'}
          </div>
        )}
      </td>

      <td className="px-3 py-3">
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
            className={`mono inline-flex w-fit items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.1em] ${priorityChipClass(pri)}`}
          >
            {priorityLabel(pri)}
          </span>
        )}
      </td>

      <td className="px-3 py-3">
        <span className="text-[13px] text-muted-foreground">{todo.examiner || todo.created_by || '—'}</span>
      </td>

      <td className="px-3 py-3">
        <span
          className={`mono inline-flex w-fit items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.1em] ${statusChipClass(stat)}`}
        >
          {stat}
        </span>
      </td>

      <td className="px-3 py-3">
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

      <td className="px-3 py-3">
        <span className="mono whitespace-nowrap text-[11px] tabular-nums text-muted-foreground">{formatDate(todo.created_at)}</span>
      </td>

      {canWrite && (
        <td className="px-3 py-3">
          <div className="flex items-center justify-end gap-1.5">
            {isEditing ? (
              <>
                <IconAction label="Save changes" onClick={() => onSaveEdit(todo)} disabled={isBusy} tone="jade">
                  <Check className="size-3.5" aria-hidden />
                </IconAction>
                <IconAction label="Cancel edit" onClick={onCancelEdit} disabled={isBusy} tone="muted">
                  <X className="size-3.5" aria-hidden />
                </IconAction>
              </>
            ) : (
              <>
                {/* Primary action: single-click status toggle. */}
                <IconAction
                  label={completed ? 'Reopen' : 'Complete'}
                  onClick={() => onToggleStatus(todo)}
                  disabled={isBusy}
                  tone={completed ? 'muted' : 'jade'}
                >
                  {completed ? <RotateCcw className="size-3.5" aria-hidden /> : <Check className="size-3.5" aria-hidden />}
                </IconAction>

                {/* Overflow menu: edit / delete (no cramming — contract B8). */}
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <button
                      type="button"
                      aria-label="More actions"
                      disabled={isBusy}
                      className="inline-flex size-7 items-center justify-center rounded-md border border-border-soft bg-bg-raised text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <MoreHorizontal className="size-3.5" aria-hidden />
                    </button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-40">
                    <DropdownMenuItem onSelect={() => onStartEdit(todo)} className="gap-2 text-xs">
                      <Pencil className="size-3.5" aria-hidden />
                      Edit
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      variant="destructive"
                      onSelect={() => onDelete(todo)}
                      className="gap-2 text-xs"
                    >
                      <Trash2 className="size-3.5" aria-hidden />
                      Delete
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </>
            )}
          </div>
        </td>
      )}
    </tr>
  )
}
