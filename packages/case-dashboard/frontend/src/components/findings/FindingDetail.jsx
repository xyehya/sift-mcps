import { useState } from 'react'
import { Check, Layers, Lock, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import {
  confClass,
  confidenceScore,
  confidenceGrade,
  effectiveFinding,
  normStatus,
  statusMeta,
} from '@/components/findings/findings-utils'
import { ConfChip, HashChip, AttChip } from '@/components/findings/FindingDetailChips'
import { AuditTrailPanel } from '@/components/findings/AuditTrailPanel'
import { FieldSection } from '@/components/findings/FindingField'
import { ObservationIcon, InterpretationIcon, CustodyIcon } from '@/components/findings/field-icons'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

// ─────────────────────────────────────────────────────────────────────────
// FindingDetail (handoff §"Right pane") — pinned header chips + 3 handoff
// fields (Observation·fact / Interpretation·analysis / Justification & custody)
// each with Edit / Redact / Expand controls + footer actions (Approve / Stage /
// Reject). RBAC: when `canReview` is false all action affordances are hidden.
//
// OLD field set (Description / Narrative / Confidence-&-Justification) has been
// removed per handoff spec — replaced by the 3 fields above. The field editor
// and header chips live in sibling modules (FindingField / FindingDetailChips)
// to keep this file under §7's ceiling.
//
// F2 (operator decision, 2026-06-22): Approve is IMMEDIATE — onApprove() stages
// a reversible `approve` delta, exactly like Stage/Reject. The step-up password
// modal was dropped. This deviates from the handoff's "step-up on Approve"; the
// real irreversible auth gate stays at Commit-to-record (server-re-authed via
// postCommit({password})→Supabase), so a password on the reversible Approve was
// friction-theater + inconsistent with Stage/Reject.
// ─────────────────────────────────────────────────────────────────────────

// ── Footer action button (Approve / Stage / Reject) ────────────────────
// Accent classes are literal token utilities (§5 pattern), not interpolated.
const FOOTER_ACCENT = {
  jade:    'bg-jade/15 border-jade/40 text-jade',
  violet:  'bg-violet/12 border-violet/35 text-violet',
  crimson: 'bg-crimson/12 border-crimson/35 text-crimson',
}

function FooterAction({ accent, onClick, icon, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex items-center gap-1.5 rounded-[8px] border px-3 py-1.5 text-[12px] font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        FOOTER_ACCENT[accent],
      )}
    >
      {icon}
      {children}
    </button>
  )
}

// ── FindingDetail export ───────────────────────────────────────────────

export function FindingDetail({
  finding, stagedItem, canReview,
  addToast,
  onApprove, onStage, onReject, onUnstage, onEdit,
}) {
  // FindingDetail is keyed by finding.id in the parent so it remounts whenever
  // the selected finding changes — no reset effect needed.
  const [editingField, setEditingField] = useState(null)

  const eff = effectiveFinding(finding, stagedItem)
  const mods = stagedItem?.modifications ?? {}

  const conf = confClass(eff.confidence)
  const status = normStatus(finding)
  const sMeta = statusMeta(status)
  // Once a finding is committed to the record it leaves the delta (stagedItem is
  // null) and falls into the action-cluster branch below — so terminal states
  // must be locked read-only there. Stage is independently restricted to drafts.
  const isTerminal = ['approved', 'rejected', 'committed', 'superseded'].includes(status)

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
      <header className="shrink-0 border-b border-border-soft bg-bg-raised px-5 pt-4 pb-3">
        {/* Chip row */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-display text-[20px] font-bold tracking-[-.2px] text-text-bright">
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

          <span className="flex-1" />

          {/* ATT&CK chip */}
          <AttChip attId={attId} />

          {/* Confidence chip */}
          <ConfChip score={score} grade={grade} />

          {/* Hash chip */}
          <HashChip evId={evId} sha={sha} />
        </div>

        {/* Title + host · timestamp */}
        <h2 className="mt-2 text-[14px] font-semibold leading-snug text-text-bright">
          {eff.title}
        </h2>
        {(eff.host || eventTs) && (
          <p className="mono mt-1 text-[11px] text-text-muted">
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

        {/* Audit-trail provenance (B4): surfaces the finding's audit_ids — the
            tool-call chain behind it. Only renders when audit_ids are present;
            AuditTrailPanel degrades to id-only rows when getAudit resolves empty. */}
        {finding.audit_ids?.length > 0 && (
          <div className="border-t border-border-soft pt-5">
            <AuditTrailPanel finding={finding} />
          </div>
        )}
      </div>

      {/* ── Footer actions ───────────────────────────────────────────── */}
      <div className="flex shrink-0 items-center gap-2 border-t border-border-soft bg-bg-surface px-5 py-3">
        {!canReview ? (
          <p className="text-xs text-muted-foreground">Read-only — sign in as an examiner to review findings.</p>
        ) : stagedItem ? (
          <Button variant="outline" size="sm" onClick={onUnstage} className="gap-1.5 text-status-staged">
            <Layers className="size-3.5" /> Undo staged {stagedItem.action}
          </Button>
        ) : isTerminal ? (
          // Committed/terminal finding (no longer in the delta): read-only. No
          // Stage/Reject/Approve — the record entry is immutable from this pane.
          <span className="flex items-center gap-1.5 text-[12px] text-text-muted">
            <Lock className="size-3.5" aria-hidden />
            Committed to record — read-only
          </span>
        ) : (
          <>
            {/* Approve — immediate (F2): stages a reversible approve delta, like
                Stage/Reject. Real auth gate is at Commit-to-record. */}
            <FooterAction
              accent="jade"
              onClick={() => {
                onApprove()
                if (addToast) addToast('Finding approved — staged for commit', 'success')
              }}
              icon={<Check className="size-3.5" aria-hidden />}
            >
              Approve
            </FooterAction>

            {/* Stage — drafts only (never on a non-draft finding). */}
            {onStage && status === 'draft' && (
              <FooterAction accent="violet" onClick={onStage} icon={<Layers className="size-3.5" aria-hidden />}>
                Stage
              </FooterAction>
            )}

            {/* Reject — immediate */}
            <FooterAction accent="crimson" onClick={onReject} icon={<X className="size-3.5" aria-hidden />}>
              Reject
            </FooterAction>
          </>
        )}
        <div className="flex-1" />
        {canReview && (
          <span className="mono hidden text-[11px] text-text-ghost sm:inline">
            j/k navigate · a approve · s stage · r reject
          </span>
        )}
      </div>
    </div>
  )
}
