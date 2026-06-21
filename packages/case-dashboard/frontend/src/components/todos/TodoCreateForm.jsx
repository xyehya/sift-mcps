// ─────────────────────────────────────────────────────────────────────────
// TodoCreateForm — examiner-only create panel (legacy parity §6): description
// (required) + priority + assignee + related-findings. Rendered only when the
// operator opens the "New TODO" toggle and has write access. Reskinned to
// graphite/orange tokens; the jade Create button signals an additive action.
// ─────────────────────────────────────────────────────────────────────────

const FIELD =
  'mono rounded-lg border border-border-soft bg-bg-raised px-2 py-1.5 text-[11px] text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

export function TodoCreateForm({ draft, onDraft, saving, onCreate }) {
  return (
    <div className="space-y-2 rounded-lg border border-border-soft bg-card p-3">
      <textarea
        autoFocus
        aria-label="Task description"
        value={draft.description}
        onChange={(e) => onDraft({ ...draft, description: e.target.value })}
        placeholder="Describe the task…"
        rows={2}
        className="w-full resize-y rounded-lg border border-border-soft bg-bg-raised px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
      />
      <div className="flex flex-wrap items-center gap-2">
        <select
          aria-label="Priority"
          value={draft.priority}
          onChange={(e) => onDraft({ ...draft, priority: e.target.value })}
          className={FIELD}
        >
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <input
          aria-label="Assignee"
          value={draft.assignee}
          onChange={(e) => onDraft({ ...draft, assignee: e.target.value })}
          placeholder="Assignee (optional)"
          className={FIELD}
        />
        <input
          aria-label="Related findings"
          value={draft.related}
          onChange={(e) => onDraft({ ...draft, related: e.target.value })}
          placeholder="Related findings, comma-separated (optional)"
          className={`${FIELD} min-w-[16rem] flex-1`}
        />
        <button
          type="button"
          onClick={onCreate}
          disabled={saving}
          className="mono rounded-lg border border-jade bg-jade/10 px-3 py-1.5 text-[11px] font-semibold text-status-approved transition-opacity hover:opacity-85 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Create'}
        </button>
      </div>
    </div>
  )
}
