import { useState } from 'react'
import { Check, Layers, X } from 'lucide-react'

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
import { FieldSection } from '@/components/findings/FindingField'
import { ObservationIcon, InterpretationIcon, CustodyIcon } from '@/components/findings/field-icons'
import { StepUpApproveModal } from '@/components/findings/StepUpApproveModal'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

// ─────────────────────────────────────────────────────────────────────────
// FindingDetail (handoff §"Right pane") — pinned header chips + 3 handoff
// fields (Observation·fact / Interpretation·analysis / Justification & custody)
// each with Edit / Redact / Expand controls + footer actions (Approve / Stage /
// Reject). RBAC: when `canReview` is false all action affordances are hidden.
//
// OLD field set (Description / Narrative / Confidence-&-Justification) has been
// removed per handoff spec — replaced by the 3 fields above. The field editor,
// header chips, and step-up modal live in sibling modules (FindingField /
// FindingDetailChips / StepUpApproveModal) to keep this file under §7's ceiling.
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
  stepUpOpen, onStepUpClose, onStepUpOpen,
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
      </div>

      {/* ── Footer actions ───────────────────────────────────────────── */}
      <div className="flex shrink-0 items-center gap-2 border-t border-border-soft bg-bg-surface px-5 py-3">
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
              <FooterAction accent="jade" onClick={() => onStepUpOpen?.()} icon={<Check className="size-3.5" aria-hidden />}>
                Approve
              </FooterAction>
            )}

            {/* Stage — immediate */}
            {onStage && (
              <FooterAction accent="violet" onClick={onStage} icon={<Layers className="size-3.5" aria-hidden />}>
                Stage
              </FooterAction>
            )}

            {/* Reject — immediate */}
            {status !== 'rejected' && (
              <FooterAction accent="crimson" onClick={onReject} icon={<X className="size-3.5" aria-hidden />}>
                Reject
              </FooterAction>
            )}
          </>
        )}
        <div className="flex-1" />
        {canReview && (
          <span className="mono hidden text-[11px] text-text-ghost sm:inline">
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
          // Prototype: the password is NOT verified — onApprove() only STAGES a
          // reversible delta (the real irreversible gate, Commit-to-record, IS
          // server-re-authed: CommitDrawer → postCommit({password}) → Supabase, CL3a).
          // TODO(CG-AUTH): either drop this modal (Approve only stages) OR re-auth the
          // password server-side via the LIVE plaintext-password→Supabase pattern
          // (mirror postCommit/unsealEvidence({password})). NOTE: api/crypto.js
          // computeChallengeResponse is DEAD CODE — do NOT wire to it.
          onStepUpClose?.()
          onApprove()
          if (addToast) addToast('Finding approved (prototype — auth pending)', 'success')
        }}
      />
    </div>
  )
}
