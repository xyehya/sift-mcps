import { useState } from 'react'
import { Check, Pencil, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { getTagString } from '@/components/findings/findings-utils'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

// ─────────────────────────────────────────────────────────────────────────
// EditableField — inline examiner edit primitive (textarea / tag-list /
// select). Ported from the old FindingsTab edit logic, restyled to tokens and
// self-contained: it owns its draft state and emits onSave(newValue) so the
// parent only tracks which field is open + persists the delta. When a staged
// modification exists it shows the original → modified diff. RBAC: when
// `canEdit` is false the pencil affordance is hidden (read-only examiner view).
// All values render as escaped React text — no HTML injection sink.
// ─────────────────────────────────────────────────────────────────────────

function initDraft(kind, value) {
  if (kind === 'tags') return Array.isArray(value) ? value.map(getTagString) : []
  return value ?? ''
}

export function EditableField({
  kind = 'textarea',
  label,
  value,
  modification,
  editing,
  canEdit = false,
  onStartEdit,
  onSave,
  onCancel,
  options = [],
  placeholder,
  rows = 3,
}) {
  const [draft, setDraft] = useState(() => initDraft(kind, value))
  const [tagInput, setTagInput] = useState('')

  // Re-seed the draft when this field enters edit mode. Done during render via
  // the "previous prop" pattern (not an effect) so there is no cascading-render
  // setState-in-effect and the editor opens already populated.
  const [wasEditing, setWasEditing] = useState(editing)
  if (editing !== wasEditing) {
    setWasEditing(editing)
    if (editing) {
      setDraft(initDraft(kind, value))
      setTagInput('')
    }
  }

  function addTag() {
    const v = tagInput.trim()
    if (v && !draft.map(getTagString).includes(v)) setDraft([...draft, v])
    setTagInput('')
  }

  // ---------- edit mode ----------
  if (editing) {
    return (
      <div className="mt-1.5 space-y-2">
        {kind === 'tags' ? (
          <div className="flex flex-wrap gap-1.5 rounded-md border border-input bg-transparent p-2">
            {draft.map((t) => {
              const s = getTagString(t)
              return (
                <span key={s} className="mono inline-flex items-center gap-1 rounded bg-secondary px-1.5 py-0.5 text-[11px]">
                  {s}
                  <button
                    type="button"
                    onClick={() => setDraft(draft.filter((x) => getTagString(x) !== s))}
                    aria-label={`Remove ${s}`}
                    className="text-muted-foreground hover:text-destructive"
                  >
                    <X className="size-3" />
                  </button>
                </span>
              )
            })}
            <input
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  addTag()
                }
              }}
              placeholder="Add + Enter"
              aria-label={`Add ${label}`}
              className="mono w-28 bg-transparent text-[11px] outline-none placeholder:text-muted-foreground"
            />
          </div>
        ) : kind === 'select' ? (
          <Select value={draft} onValueChange={setDraft}>
            <SelectTrigger size="sm" className="w-48" aria-label={label}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {options.map((o) => (
                <SelectItem key={o} value={o}>
                  {o}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : (
          <Textarea
            rows={rows}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={placeholder ?? `Edit ${label}…`}
            aria-label={label}
            className="text-xs"
          />
        )}
        <div className="flex gap-2">
          <Button type="button" size="xs" onClick={() => onSave(draft)} className="gap-1">
            <Check className="size-3" /> Save
          </Button>
          <Button type="button" size="xs" variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </div>
    )
  }

  // ---------- staged-diff display ----------
  if (modification) {
    return (
      <div className="mt-1 space-y-1 text-xs">
        <DiffValue kind={kind} value={modification.original} tone="muted" strike />
        <DiffValue kind={kind} value={modification.modified} tone="staged" />
      </div>
    )
  }

  // ---------- plain display ----------
  return (
    <div className="mt-1 flex items-start gap-1.5">
      <div className="min-w-0 flex-1">
        {kind === 'tags' ? (
          <TagList value={value} />
        ) : (
          <p className="whitespace-pre-wrap text-xs leading-relaxed text-foreground">
            {value ? String(value) : <span className="text-muted-foreground">Empty.</span>}
          </p>
        )}
      </div>
      {canEdit && (
        <button
          type="button"
          onClick={onStartEdit}
          aria-label={`Edit ${label}`}
          className="shrink-0 rounded p-0.5 text-muted-foreground transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Pencil className="size-3" />
        </button>
      )}
    </div>
  )
}

function TagList({ value }) {
  const items = Array.isArray(value) ? value : []
  if (items.length === 0) return <p className="mono text-xs italic text-muted-foreground">None.</p>
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((t) => {
        const s = getTagString(t)
        return (
          <span key={s} className="mono rounded border border-border bg-secondary px-1.5 py-0.5 text-[11px] text-muted-foreground">
            {s}
          </span>
        )
      })}
    </div>
  )
}

function DiffValue({ kind, value, tone, strike }) {
  const toneClass = tone === 'staged' ? 'text-status-staged' : 'text-muted-foreground'
  if (kind === 'tags') {
    const items = Array.isArray(value) ? value : []
    return (
      <div className={cn('flex flex-wrap gap-1', strike && 'line-through')}>
        {items.map((t) => {
          const s = getTagString(t)
          return (
            <span key={s} className={cn('mono rounded border border-border px-1.5 py-0.5 text-[11px]', toneClass)}>
              {s}
            </span>
          )
        })}
      </div>
    )
  }
  return <p className={cn('whitespace-pre-wrap', toneClass, strike && 'line-through')}>{String(value || '(empty)')}</p>
}
