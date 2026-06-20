import { useRef, useState } from 'react'
import { Check, KeyRound, Layers, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import {
  confClass,
  confidenceScore,
  confidenceGrade,
  effectiveFinding,
  normStatus,
  statusMeta,
} from '@/components/findings/findings-utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'

// ─────────────────────────────────────────────────────────────────────────
// FindingDetail (handoff §"Right pane") — pinned header chips + 3 handoff
// fields (Observation·fact / Interpretation·analysis / Justification & custody)
// each with Edit / Redact / Expand controls + footer actions (Approve / Stage /
// Reject). RBAC: when `canReview` is false all action affordances are hidden.
//
// OLD field set (Description / Narrative / Confidence-&-Justification) has been
// removed per handoff spec — replaced by the 3 fields above.
// ─────────────────────────────────────────────────────────────────────────

// ── Step-up modal ──────────────────────────────────────────────────────

/**
 * StepUpApproveModal — password-gated approval dialog (handoff model-shift §3).
 * The "Authorize & approve" button is disabled until a non-empty password is
 * entered. Prototype accepts any non-empty password; production wires to real
 * step-up auth.
 */
function StepUpApproveModal({ findingId, open, onClose, onConfirm }) {
  const [pass, setPass] = useState('')
  const inputRef = useRef(null)

  const handleOpenChange = (next) => {
    if (!next) { setPass(''); onClose() }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent
        className="max-w-sm"
        onOpenAutoFocus={(e) => { e.preventDefault(); inputRef.current?.focus() }}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm font-semibold">
            <KeyRound className="size-4 text-status-approved" aria-hidden />
            Step-up authorization · Approve {findingId}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 text-xs">
          <p className="leading-relaxed text-muted-foreground">
            Approving a finding is a chain-of-custody action. Enter your examiner password to authorize.
          </p>
          <div className="space-y-1.5">
            {/* text-xs — meets WCAG resize requirement for form labels */}
            <label htmlFor="stepup-pass" className="mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Examiner password
            </label>
            <Input
              ref={inputRef}
              id="stepup-pass"
              type="password"
              value={pass}
              onChange={(e) => setPass(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && pass) onConfirm(pass) }}
              placeholder="Enter password…"
              autoComplete="current-password"
              className="h-9 text-sm"
            />
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" size="sm" onClick={() => { setPass(''); onClose() }}>
            Cancel
          </Button>
          <Button
            type="button"
            size="sm"
            disabled={!pass}
            onClick={() => {
              // TODO(CG-AUTH): wire onConfirm(pass) → computeChallengeResponse() → POST /api/auth/step-up-approve (see EvidenceUnseal)
              onConfirm(pass)
            }}
            className="gap-1.5 bg-status-approved text-primary-foreground hover:bg-status-approved/90 disabled:opacity-50"
          >
            <Check className="size-3.5" aria-hidden />
            Authorize &amp; approve
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ── Confidence chip (colored dot + NN%) ────────────────────────────────

function ConfChip({ score, grade }) {
  if (score == null) return null
  const title = `Model confidence · ${score}%`
  return (
    <span
      title={title}
      className="mono inline-flex cursor-default items-center gap-1.5 rounded-[7px] border px-2 py-1 text-[11px] font-semibold"
      style={{
        color: grade?.text ? undefined : 'var(--text-muted)',
        borderColor: 'var(--border-soft)',
        background: 'var(--bg-raised)',
      }}
    >
      <span
        aria-hidden
        className="inline-block size-[7px] shrink-0 rounded-full"
        style={{ background: grade?.stroke ?? 'var(--text-muted)' }}
      />
      <span style={{ color: grade?.stroke ?? 'var(--text-muted)' }}>{score}%</span>
    </span>
  )
}

// ── Hash chip (jade seal icon + EV-id, hover = full sha256) ────────────

function HashChip({ evId, sha }) {
  if (!evId && !sha) return null
  const label = evId ?? 'EV'
  const title = sha ? `sha256:${sha} · ${label}` : label
  return (
    <span
      title={title}
      className="mono inline-flex cursor-default items-center gap-1.5 rounded-[7px] border px-2 py-1 text-[11px] font-semibold"
      style={{ color: 'var(--text-muted)', borderColor: 'var(--border-soft)', background: 'var(--bg-raised)' }}
    >
      {/* jade seal / shield-check icon */}
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--jade)" strokeWidth="1.9" aria-hidden>
        <path d="M12 3l7 3v6c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V6z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
      {label}
    </span>
  )
}

// ── ATT&CK chip ─────────────────────────────────────────────────────────

function AttChip({ attId }) {
  if (!attId) return null
  return (
    <span
      className="mono inline-flex cursor-default items-center rounded-[7px] border px-2 py-1 text-[11px] font-semibold"
      style={{ color: 'var(--text-muted)', borderColor: 'var(--border-soft)', background: 'var(--bg-raised)' }}
    >
      ATT&amp;CK {attId}
    </span>
  )
}

// ── Field control buttons (Edit / Redact / Expand) ─────────────────────

function ControlBtn({ active, activeColor, title, onClick, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className="flex size-6 items-center justify-center rounded-[5px] border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      style={{
        background: active ? `color-mix(in srgb,${activeColor} 14%,transparent)` : 'transparent',
        borderColor: active ? `color-mix(in srgb,${activeColor} 30%,transparent)` : 'var(--border-soft)',
        color: active ? activeColor : 'var(--text-ghost)',
      }}
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
      <span className="mono text-[11px] font-semibold uppercase tracking-[.12em]" style={{ color: 'var(--text-muted)' }}>
        {label}
      </span>
      <div className="flex-1" />
      {/* Edit */}
      <ControlBtn active={editing} activeColor="var(--orange)" title={editing ? 'Cancel edit' : 'Edit'} onClick={onEdit}>
        {/* pencil icon */}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" aria-hidden>
          <path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>
        </svg>
      </ControlBtn>
      {/* Redact */}
      <ControlBtn active={redacted} activeColor="var(--crimson)" title={redacted ? 'Unredact' : 'Redact'} onClick={onRedact}>
        {/* eye icon */}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" aria-hidden>
          <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/>
          <circle cx="12" cy="12" r="2.6"/>
        </svg>
      </ControlBtn>
      {/* Expand */}
      <ControlBtn active={expanded} activeColor="var(--steel)" title={expanded ? 'Collapse' : 'Expand'} onClick={onExpand}>
        {/* expand icon */}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" aria-hidden>
          <path d="M8 3H5a2 2 0 0 0-2 2v3M16 3h3a2 2 0 0 1 2 2v3M21 16v3a2 2 0 0 1-2 2h-3M3 16v3a2 2 0 0 0 2 2h3"/>
        </svg>
      </ControlBtn>
    </div>
  )
}

// ── Single editable field section ──────────────────────────────────────

function FieldSection({ icon, label, value, monoBody, editingField, setEditingField, canEdit, fieldKey, onSave, modification }) {
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
            'overflow-hidden whitespace-pre-wrap text-[12.5px] leading-relaxed transition-all',
            monoBody && 'font-mono text-[11.5px]',
          )}
          style={{
            maxHeight: MAX_H,
            overflowY: expanded ? 'auto' : 'hidden',
            filter: redacted ? 'blur(5px)' : 'none',
            userSelect: redacted ? 'none' : 'auto',
            color: 'var(--text-primary)',
          }}
        >
          {modification
            ? String(modification.modified || value || '')
            : (value ? String(value) : <span style={{ color: 'var(--text-ghost)' }}>—</span>)
          }
        </p>
      )}
    </section>
  )
}

// ── Icons for the 3 fields ─────────────────────────────────────────────

const ObservationIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--jade)" strokeWidth="1.9" aria-hidden style={{ flex: 'none' }}>
    <circle cx="11" cy="11" r="7"/>
    <path d="m20 20-3.5-3.5M8.5 11l1.8 1.8L14 9"/>
  </svg>
)

const InterpretationIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" strokeWidth="1.9" aria-hidden style={{ flex: 'none' }}>
    <path d="M9 18h6M10 21h4M12 3a6 6 0 0 1 4 10.5c-.7.7-1 1.2-1 2.5H9c0-1.3-.3-1.8-1-2.5A6 6 0 0 1 12 3Z"/>
  </svg>
)

const CustodyIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--steel)" strokeWidth="1.9" aria-hidden style={{ flex: 'none' }}>
    <path d="M12 3v18M7 7l5-3 5 3M5 11h14M5 11l-2 4a3 3 0 0 0 4 0zM19 11l-2 4a3 3 0 0 0 4 0z"/>
  </svg>
)

// ── FindingDetail export ───────────────────────────────────────────────

export function FindingDetail({
  finding, stagedItem, timeline: _timeline, canReview,
  addToast,
  stepUpOpen, onStepUpClose, onStepUpOpen,
  onApprove, onStage, onReject, onUnstage, onEdit, onNavigate: _onNavigate,
}) {
  // FindingDetail is keyed by finding.id in the parent so it remounts whenever
  // the selected finding changes — no reset effect needed.
  const [editingField, setEditingField] = useState(null)

  const eff = effectiveFinding(finding, stagedItem)
  const mods = stagedItem?.modifications ?? {}

  const conf = confClass(eff.confidence)
  const status = normStatus(finding)
  const sMeta = statusMeta(status)

  const score = confidenceScore(eff)
  const grade = confidenceGrade(score)

  // First ATT&CK id
  const attId = eff.mitre_ids?.[0] ?? null

  // Evidence/sha from fixture fields
  const evId = eff.ev ?? eff.evidence_id ?? null
  const sha = eff.sha ?? eff.content_hash ?? null

  const eventTs = eff.event_timestamp || eff.timestamp

  function handleSave(field, original, modified) {
    if (String(modified ?? '') === String(original ?? '')) {
      setEditingField(null)
      return
    }
    onEdit(field, original, modified)
    setEditingField(null)
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* ── Pinned header (does NOT scroll with body) ─────────────── */}
      <header
        className="shrink-0 border-b px-5 pt-4 pb-3"
        style={{ borderColor: 'var(--border-soft)', background: 'var(--bg-raised)' }}
      >
        {/* Chip row */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span
            className="font-display font-bold"
            style={{ fontSize: '20px', color: 'var(--text-bright)', letterSpacing: '-.2px' }}
          >
            {finding.id}
          </span>

          {/* Severity chip */}
          {conf && (
            <Badge variant="outline" className={cn(conf.ring, conf.text, 'text-[11px]')}>
              {conf.label}
            </Badge>
          )}

          {/* Status chip */}
          {stagedItem ? (
            <Badge variant="outline" className="text-[11px] text-status-staged">
              staged {stagedItem.action}
            </Badge>
          ) : (
            <Badge variant="outline" className={cn(sMeta.ring, sMeta.text, 'text-[11px]')}>
              {sMeta.label}
            </Badge>
          )}

          <span style={{ flex: 1 }} />

          {/* ATT&CK chip */}
          <AttChip attId={attId} />

          {/* Confidence chip */}
          <ConfChip score={score} grade={grade} />

          {/* Hash chip */}
          <HashChip evId={evId} sha={sha} />
        </div>

        {/* Title + host · timestamp */}
        <h2
          className="mt-2 text-[14px] font-semibold leading-snug"
          style={{ color: 'var(--text-bright)' }}
        >
          {eff.title}
        </h2>
        {(eff.host || eventTs) && (
          <p className="mono mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>
            {[eff.host, eventTs ? String(eventTs).replace('T', ' ').substring(0, 19) : null].filter(Boolean).join(' · ')}
          </p>
        )}
      </header>

      {/* ── Scrollable body ─────────────────────────────────────────── */}
      <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
        {/* Staged banner */}
        {stagedItem && (
          <div className="flex items-center justify-between rounded-md border border-dashed border-status-staged/50 bg-status-staged/5 px-3 py-2 text-xs text-status-staged">
            <span>Staged for {stagedItem.action} — not yet committed.</span>
            {canReview && onUnstage && (
              <button type="button" onClick={onUnstage} className="font-semibold underline">
                Undo
              </button>
            )}
          </div>
        )}

        {/* ── THREE FIELDS (handoff spec — exactly these, no others) ── */}

        {/* 1. Observation · fact (jade, mono body) */}
        <FieldSection
          icon={ObservationIcon}
          label="Observation · fact"
          value={eff.observation}
          monoBody
          editingField={editingField}
          setEditingField={setEditingField}
          canEdit={canReview}
          fieldKey="observation"
          onSave={handleSave}
          modification={mods.observation}
        />

        {/* 2. Interpretation · analysis (amber) */}
        <FieldSection
          icon={InterpretationIcon}
          label="Interpretation · analysis"
          value={eff.interpretation}
          monoBody={false}
          editingField={editingField}
          setEditingField={setEditingField}
          canEdit={canReview}
          fieldKey="interpretation"
          onSave={handleSave}
          modification={mods.interpretation}
        />

        {/* 3. Justification & custody (steel) */}
        <FieldSection
          icon={CustodyIcon}
          label="Justification &amp; custody"
          value={eff.confidence_justification ?? eff.justification}
          monoBody={false}
          editingField={editingField}
          setEditingField={setEditingField}
          canEdit={canReview}
          fieldKey="confidence_justification"
          onSave={handleSave}
          modification={mods.confidence_justification}
        />
      </div>

      {/* ── Footer actions ───────────────────────────────────────────── */}
      <div className="flex shrink-0 items-center gap-2 border-t px-5 py-3" style={{ borderColor: 'var(--border-soft)', background: 'var(--bg-surface)' }}>
        {!canReview ? (
          <p className="text-xs text-muted-foreground">Read-only — sign in as an examiner to review findings.</p>
        ) : stagedItem ? (
          <Button variant="outline" size="sm" onClick={onUnstage} className="gap-1.5 text-status-staged">
            <Layers className="size-3.5" /> Undo staged {stagedItem.action}
          </Button>
        ) : (
          <>
            {/* Approve — password-gated (step-up) */}
            {status !== 'approved' && (
              <button
                type="button"
                onClick={() => onStepUpOpen?.()}
                className="flex items-center gap-1.5 rounded-[8px] border px-3 py-1.5 text-[12px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                style={{
                  background: 'color-mix(in srgb,var(--jade) 14%,transparent)',
                  borderColor: 'color-mix(in srgb,var(--jade) 40%,transparent)',
                  color: 'var(--jade)',
                }}
              >
                <Check className="size-3.5" aria-hidden />
                Approve
              </button>
            )}

            {/* Stage — immediate */}
            {onStage && (
              <button
                type="button"
                onClick={onStage}
                className="flex items-center gap-1.5 rounded-[8px] border px-3 py-1.5 text-[12px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                style={{
                  background: 'color-mix(in srgb,var(--violet) 12%,transparent)',
                  borderColor: 'color-mix(in srgb,var(--violet) 36%,transparent)',
                  color: 'var(--violet)',
                }}
              >
                <Layers className="size-3.5" aria-hidden />
                Stage
              </button>
            )}

            {/* Reject — immediate */}
            {status !== 'rejected' && (
              <button
                type="button"
                onClick={onReject}
                className="flex items-center gap-1.5 rounded-[8px] border px-3 py-1.5 text-[12px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                style={{
                  background: 'color-mix(in srgb,var(--crimson) 12%,transparent)',
                  borderColor: 'color-mix(in srgb,var(--crimson) 36%,transparent)',
                  color: 'var(--crimson)',
                }}
              >
                <X className="size-3.5" aria-hidden />
                Reject
              </button>
            )}
          </>
        )}
        <div className="flex-1" />
        {canReview && (
          <span className="mono hidden text-[11px] sm:inline" style={{ color: 'var(--text-ghost)' }}>
            j/k navigate · a approve · s stage · r reject
          </span>
        )}
      </div>

      {/* ── Step-up modal (Approve) ──────────────────────────────────── */}
      <StepUpApproveModal
        findingId={finding.id}
        open={!!stepUpOpen}
        onClose={() => onStepUpClose?.()}
        onConfirm={() => {
          // Prototype accepts any non-empty password; production wires to real step-up auth.
          // TODO(CG-AUTH): wire onConfirm(pass) → computeChallengeResponse() → POST /api/auth/step-up-approve (see EvidenceUnseal)
          onStepUpClose?.()
          onApprove()
          if (addToast) addToast('Finding approved (prototype — auth pending)', 'success')
        }}
      />
    </div>
  )
}
