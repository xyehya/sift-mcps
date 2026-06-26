import { useState } from 'react'
import { Check } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'

// ─────────────────────────────────────────────────────────────────────────
// FindingField — one editable handoff field (Observation / Interpretation /
// Justification) with its Edit / Redact / Expand control row + staged-diff +
// inline textarea editor. The `icon` is supplied by the caller (field-icons).
// Colors are literal token classes (CTRL_ACCENT map, §5 CONF_CLASS pattern);
// the redact blur + max-height are data-driven numeric styles per §11.
// ─────────────────────────────────────────────────────────────────────────

// ── Control-button accent classes (literal — JIT-safe, no interpolation) ──
// Each accent supplies an active (washed bg + border + colored glyph) and an
// inactive (transparent, ghost glyph) variant.
const CTRL_ACCENT = {
  orange:  { active: 'bg-orange/15 border-orange/30 text-orange',   inactive: 'border-border-soft text-text-ghost' },
  crimson: { active: 'bg-crimson/15 border-crimson/30 text-crimson', inactive: 'border-border-soft text-text-ghost' },
  steel:   { active: 'bg-steel/15 border-steel/30 text-steel',       inactive: 'border-border-soft text-text-ghost' },
}

function ControlBtn({ active, accent, title, onClick, children }) {
  const tone = CTRL_ACCENT[accent] ?? CTRL_ACCENT.steel
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={cn(
        'flex size-6 items-center justify-center rounded-[5px] border bg-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        active ? tone.active : tone.inactive,
      )}
    >
      {children}
    </button>
  )
}

// ── Field header row ───────────────────────────────────────────────────

function FieldHeader({ icon, label, onEdit, onRedact, onExpand, editing, redacted, expanded }) {
  return (
    <div className="mb-2 flex items-center gap-2">
      {icon}
      <span className="mono text-[11px] font-semibold uppercase tracking-[.12em] text-text-muted">
        {label}
      </span>
      <div className="flex-1" />
      {/* Edit */}
      <ControlBtn active={editing} accent="orange" title={editing ? 'Cancel edit' : 'Edit'} onClick={onEdit}>
        {/* pencil icon */}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" aria-hidden>
          <path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>
        </svg>
      </ControlBtn>
      {/* Redact */}
      <ControlBtn active={redacted} accent="crimson" title={redacted ? 'Unredact' : 'Redact'} onClick={onRedact}>
        {/* eye icon */}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" aria-hidden>
          <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/>
          <circle cx="12" cy="12" r="2.6"/>
        </svg>
      </ControlBtn>
      {/* Expand */}
      <ControlBtn active={expanded} accent="steel" title={expanded ? 'Collapse' : 'Expand'} onClick={onExpand}>
        {/* expand icon */}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" aria-hidden>
          <path d="M8 3H5a2 2 0 0 0-2 2v3M16 3h3a2 2 0 0 1 2 2v3M21 16v3a2 2 0 0 1-2 2h-3M3 16v3a2 2 0 0 0 2 2h3"/>
        </svg>
      </ControlBtn>
    </div>
  )
}

// ── Single editable field section ──────────────────────────────────────

export function FieldSection({ icon, label, value, monoBody, editingField, setEditingField, canEdit, fieldKey, onSave, modification }) {
  const [draft, setDraft] = useState(value ?? '')
  const [redacted, setRedacted] = useState(false)
  const [expanded, setExpanded] = useState(false)

  const editing = editingField === fieldKey

  const MAX_H = expanded ? '999px' : '160px'

  function startEdit() {
    if (editing) {
      setEditingField(null)
    } else {
      setDraft(value ?? '')
      setEditingField(fieldKey)
    }
  }

  function handleSave() {
    onSave(fieldKey, value, draft)
    setEditingField(null)
  }

  return (
    <section className="space-y-0">
      <FieldHeader
        icon={icon}
        label={label}
        editing={editing}
        redacted={redacted}
        expanded={expanded}
        onEdit={canEdit ? startEdit : undefined}
        onRedact={() => setRedacted((v) => !v)}
        onExpand={() => setExpanded((v) => !v)}
      />

      {/* Staged modification diff */}
      {modification && !editing && (
        <div className="mb-1 space-y-1 text-xs">
          <p className="whitespace-pre-wrap text-muted-foreground line-through">{String(modification.original || '(empty)')}</p>
          <p className="whitespace-pre-wrap text-status-staged">{String(modification.modified || '(empty)')}</p>
        </div>
      )}

      {editing ? (
        <div className="space-y-2">
          <Textarea
            rows={5}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            aria-label={label}
            className={cn('text-xs', monoBody && 'font-mono')}
          />
          <div className="flex gap-2">
            <Button type="button" size="xs" onClick={handleSave} className="gap-1">
              <Check className="size-3" /> Save
            </Button>
            <Button type="button" size="xs" variant="ghost" onClick={() => setEditingField(null)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <p
          className={cn(
            'overflow-hidden whitespace-pre-wrap text-[12.5px] leading-relaxed text-text-primary transition-all',
            monoBody && 'font-mono text-[11.5px]',
          )}
          // Data-driven numeric styles (max-height clamp + redact blur) per §11.
          style={{
            maxHeight: MAX_H,
            overflowY: expanded ? 'auto' : 'hidden',
            filter: redacted ? 'blur(5px)' : 'none',
            userSelect: redacted ? 'none' : 'auto',
          }}
        >
          {modification
            ? String(modification.modified || value || '')
            : (value ? String(value) : <span className="text-text-ghost">—</span>)
          }
        </p>
      )}
    </section>
  )
}
