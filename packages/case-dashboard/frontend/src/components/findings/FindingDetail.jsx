import { useMemo, useState } from 'react'
import { Check, Layers, Pencil, RotateCcw, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import {
  confClass,
  contextWindow,
  effectiveFinding,
  getTagString,
  normStatus,
  statusMeta,
} from '@/components/findings/findings-utils'
import { ConfidenceRing } from '@/components/findings/ConfidenceRing'
import { EditableField } from '@/components/findings/EditableField'
import { FindingDetailSidebar } from '@/components/findings/FindingDetailSidebar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// Finding detail (review pane). Header + narrative (editable) + confidence +
// evidence/context sidebar + review action bar. Owns the single-field edit
// model (one open editor at a time) and delegates persistence to the parent
// via `onEdit` (delta contract preserved). RBAC: when `canReview` is false all
// approve/reject/edit affordances are hidden and a read-only notice is shown.
// ─────────────────────────────────────────────────────────────────────────

const CONF_OPTIONS = ['SPECULATIVE', 'LOW', 'MEDIUM', 'HIGH']
const NARRATIVE = [
  ['description', 'Description'],
  ['body', 'Narrative'],
  ['observation', 'Observation (fact)'],
  ['interpretation', 'Interpretation (analysis)'],
]

function Label({ children }) {
  return <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">{children}</p>
}

function normValue(v) {
  return Array.isArray(v) ? JSON.stringify(v.map(getTagString).sort()) : String(v ?? '')
}

/** Read-only MITRE ATT&CK technique chips (mono T-codes) for the detail header. */
function MitreChips({ ids }) {
  if (!ids?.length) return null
  return (
    <div className="mt-2.5 flex flex-wrap items-center gap-1.5" aria-label="MITRE ATT&CK techniques">
      <span className="mono text-[10px] uppercase tracking-wider text-muted-foreground">ATT&amp;CK</span>
      {ids.map((id) => (
        <Tooltip key={id}>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="mono cursor-default text-[10px]">{id}</Badge>
          </TooltipTrigger>
          <TooltipContent>MITRE ATT&CK technique {id}</TooltipContent>
        </Tooltip>
      ))}
    </div>
  )
}

export function FindingDetail({ finding, stagedItem, timeline, canReview, onApprove, onStage, onReject, onUnstage, onEdit, onNavigate }) {
  // FindingDetail is keyed by finding.id in the parent, so it remounts (and the
  // single-editor state resets) whenever the selected finding changes — no
  // reset effect needed.
  const [editingField, setEditingField] = useState(null)
  const [titleDraft, setTitleDraft] = useState('')

  const eff = useMemo(() => effectiveFinding(finding, stagedItem), [finding, stagedItem])
  const contextEvents = useMemo(() => contextWindow(finding, timeline), [finding, timeline])
  const conf = confClass(eff.confidence)
  const status = normStatus(finding)
  const sMeta = statusMeta(status)
  const mods = stagedItem?.modifications ?? {}

  function startEdit(field) {
    if (field === 'title') setTitleDraft(eff.title ?? '')
    setEditingField(field)
  }
  function cancel() {
    setEditingField(null)
  }
  async function save(field, newValue) {
    if (normValue(newValue) === normValue(finding[field])) {
      setEditingField(null)
      return
    }
    await onEdit(field, finding[field], newValue)
    setEditingField(null)
  }
  const edit = { editingField, canEdit: canReview, onStartEdit: startEdit, onSave: save, onCancel: cancel }

  const eventTs = eff.event_timestamp || eff.timestamp
  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="flex-1 space-y-5 overflow-y-auto p-5">
        {/* Header */}
        <header className={cn('-mx-5 -mt-5 border-b border-border bg-card px-5 py-4', conf && `border-l-2 ${conf.ring}`)}>
          <div className="flex items-center gap-2">
            <span className="mono text-sm text-muted-foreground">{finding.id}</span>
            {stagedItem ? (
              <Badge variant="outline" className="text-status-staged">staged {stagedItem.action}</Badge>
            ) : (
              <Badge variant="outline" className={sMeta.text}>{sMeta.label}</Badge>
            )}
          </div>

          {editingField === 'title' ? (
            <div className="mt-2 flex items-center gap-2">
              <Input value={titleDraft} onChange={(e) => setTitleDraft(e.target.value)} aria-label="Finding title" className="h-8" />
              <Button size="xs" onClick={() => save('title', titleDraft)} className="gap-1">
                <Check className="size-3" /> Save
              </Button>
              <Button size="xs" variant="ghost" onClick={cancel}>Cancel</Button>
            </div>
          ) : (
            <div className="mt-1.5 flex items-start gap-3">
              <h2 className="flex-1 text-base font-semibold leading-snug text-foreground">{eff.title}</h2>
              {canReview && (
                <button
                  type="button"
                  onClick={() => startEdit('title')}
                  aria-label="Edit title"
                  className="mt-0.5 shrink-0 rounded p-0.5 text-muted-foreground hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <Pencil className="size-3.5" />
                </button>
              )}
              {/* Graded confidence ring (≥85 jade · ≥65 amber · else crimson). */}
              <ConfidenceRing finding={eff} />
            </div>
          )}

          <div className="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs">
            {conf && <Badge variant="outline" className={conf.ring + ' ' + conf.text}>Severity: {conf.label}</Badge>}
            {finding.type && <Badge variant="secondary">{finding.type}</Badge>}
            {eff.host && (
              <span className="text-muted-foreground">
                Host: <strong className="text-foreground">{eff.host}</strong>
              </span>
            )}
            {eventTs && <span className="mono text-muted-foreground">{String(eventTs).replace('T', ' ').substring(0, 19)}</span>}
          </div>

          <MitreChips ids={eff.mitre_ids} />
        </header>

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

        {/* Narrative */}
        {NARRATIVE.map(([field, label]) =>
          eff[field] || canReview ? (
            <section key={field}>
              <Label>{label}</Label>
              <EditableField
                kind="textarea"
                label={label}
                value={eff[field]}
                modification={mods[field]}
                editing={editingField === field}
                canEdit={canReview}
                onStartEdit={() => startEdit(field)}
                onSave={(v) => save(field, v)}
                onCancel={cancel}
              />
            </section>
          ) : null,
        )}

        {/* Confidence + justification */}
        <section className="space-y-2">
          <Label>Confidence &amp; justification</Label>
          <EditableField
            kind="select"
            label="Confidence"
            value={eff.confidence}
            modification={mods.confidence}
            editing={editingField === 'confidence'}
            canEdit={canReview}
            options={CONF_OPTIONS}
            onStartEdit={() => startEdit('confidence')}
            onSave={(v) => save('confidence', v)}
            onCancel={cancel}
          />
          <EditableField
            kind="textarea"
            label="Justification"
            value={eff.confidence_justification}
            modification={mods.confidence_justification}
            editing={editingField === 'confidence_justification'}
            canEdit={canReview}
            placeholder="Why this confidence level?"
            onStartEdit={() => startEdit('confidence_justification')}
            onSave={(v) => save('confidence_justification', v)}
            onCancel={cancel}
          />
        </section>

        {/* Evidence & context (collapsible) */}
        <details className="rounded-md border border-border">
          <summary className="cursor-pointer select-none px-3 py-2 text-xs font-semibold text-foreground">
            Evidence &amp; context detail
          </summary>
          <div className="flex flex-col gap-5 border-t border-border bg-background/40 p-4 md:flex-row">
            <div className="flex-1 space-y-4">
              {finding.examiner_notes?.length > 0 && (
                <section className="space-y-2">
                  <Label>Examiner notes</Label>
                  <div className="max-h-40 space-y-2 overflow-y-auto">
                    {finding.examiner_notes.map((n, i) => (
                      <div key={i} className="rounded border border-border bg-card p-2 text-xs">
                        <div className="mb-1 flex justify-between text-[10px] text-muted-foreground">
                          <span className="font-semibold text-foreground">{n.by}</span>
                          <span>{n.at ? new Date(n.at).toLocaleString() : ''}</span>
                        </div>
                        <div className="whitespace-pre-wrap text-foreground">{n.note || n.text}</div>
                      </div>
                    ))}
                  </div>
                </section>
              )}
              {(finding.approved_by || finding.rejected_by) && (
                <section className="space-y-1 text-xs text-muted-foreground">
                  <Label>Review audit</Label>
                  {finding.approved_by && (
                    <p>
                      Approved by <strong className="text-status-approved">{finding.approved_by}</strong>
                      {finding.approved_at && ` · ${new Date(finding.approved_at).toLocaleString()}`}
                    </p>
                  )}
                  {finding.rejected_by && (
                    <p>
                      Rejected by <strong className="text-status-rejected">{finding.rejected_by}</strong>
                      {finding.rejection_reason && ` · ${finding.rejection_reason}`}
                    </p>
                  )}
                </section>
              )}
            </div>
            <FindingDetailSidebar
              finding={finding}
              eff={eff}
              stagedItem={stagedItem}
              contextEvents={contextEvents}
              edit={edit}
              onNavigate={onNavigate}
            />
          </div>
        </details>
      </div>

      {/* Review action bar */}
      <div className="flex shrink-0 items-center gap-2 border-t border-border bg-card p-3">
        {!canReview ? (
          <p className="text-xs text-muted-foreground">Read-only — sign in as an examiner to review findings.</p>
        ) : stagedItem ? (
          <Button variant="outline" size="sm" onClick={onUnstage} className="gap-1.5 text-status-staged">
            <RotateCcw className="size-3.5" /> Undo staged {stagedItem.action}
          </Button>
        ) : (
          <>
            {status !== 'approved' && (
              <Button size="sm" onClick={onApprove} className="gap-1.5 bg-status-approved text-primary-foreground hover:bg-status-approved/90">
                <Check className="size-3.5" /> Approve
              </Button>
            )}
            {onStage && (
              <Button variant="outline" size="sm" onClick={onStage} className="gap-1.5 text-status-staged">
                <Layers className="size-3.5" /> Stage
              </Button>
            )}
            {status !== 'rejected' && (
              <Button variant="destructive" size="sm" onClick={onReject} className="gap-1.5">
                <X className="size-3.5" /> Reject
              </Button>
            )}
          </>
        )}
        <div className="flex-1" />
        {canReview && <span className="mono hidden text-[11px] text-muted-foreground sm:inline">j/k navigate · a approve · s stage · r reject</span>}
      </div>
    </div>
  )
}
