import { useState } from 'react'
import { Lock, ShieldX } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { blockedActions } from '@/lib/agent-state'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'

// ─────────────────────────────────────────────────────────────────────────
// BlockedActionsPane — the "Blocked actions · POLICY GUARDS · READ-ONLY"
// awareness pane (handoff §Screen 1, model-shift §3). The agent runs
// AUTONOMOUSLY; blocked tool-calls are surfaced here for examiner AWARENESS
// only — there are NO approve/deny buttons, NO authorization queue.
// Clicking a row opens a read-only detail modal (tool, target, guard,
// disposition). The badge count caps at "9+" (matching the sidebar badge).
// ─────────────────────────────────────────────────────────────────────────

const GUARD_TONE = {
  'Integrity guard': 'border-sev-high/40 text-sev-high bg-sev-high/10',
  'Read-only guard': 'border-sev-low/40 text-sev-low bg-sev-low/10',
  'Egress guard': 'border-sev-med/40 text-sev-med bg-sev-med/10',
  'Acquisition guard': 'border-status-staged/40 text-status-staged bg-status-staged/10',
  'Custody guard': 'border-sev-high/40 text-sev-high bg-sev-high/10',
}

function guardChipClass(guard) {
  return GUARD_TONE[guard] ?? 'border-border text-muted-foreground bg-secondary'
}

/** A single blocked-action row — read-only; click opens the detail modal. */
function BlockedRow({ action, onClick }) {
  return (
    <button
      type="button"
      onClick={() => onClick(action)}
      aria-label={`View blocked action: ${action.title}`}
      className={cn(
        'group flex w-full items-center gap-3 rounded-md px-1 py-2.5 text-left transition-colors',
        'hover:bg-secondary/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
      )}
    >
      <span aria-hidden className="flex size-7 shrink-0 items-center justify-center rounded-md border border-sev-high/30 bg-sev-high/10">
        <Lock className="size-3.5 text-sev-high" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-xs font-medium text-foreground">{action.title}</div>
        <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
          <span className="mono text-[10px] text-muted-foreground">{action.tool}</span>
          {action.guard && (
            <span className={cn('rounded-full border px-1.5 py-0 text-[10px] font-medium', guardChipClass(action.guard))}>
              {action.guard}
            </span>
          )}
        </div>
      </div>
      <span className="mono shrink-0 text-[10px] text-muted-foreground">{action.timestamp}</span>
      <span aria-hidden className="shrink-0 text-border transition-colors group-hover:text-muted-foreground">›</span>
    </button>
  )
}

/** Read-only detail modal for a blocked action. */
function BlockedDetailModal({ action, onClose }) {
  if (!action) return null
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-sm font-semibold">Blocked action · read-only</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 text-xs">
          <div className="space-y-1">
            <p className="font-semibold text-muted-foreground uppercase tracking-wider text-[10px] mono">Title</p>
            <p className="text-foreground font-medium">{action.title}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <p className="font-semibold text-muted-foreground uppercase tracking-wider text-[10px] mono">Tool</p>
              <p className="mono text-foreground">{action.tool}</p>
            </div>
            <div className="space-y-1">
              <p className="font-semibold text-muted-foreground uppercase tracking-wider text-[10px] mono">Guard</p>
              {action.guard ? (
                <span className={cn('rounded-full border px-2 py-0.5 text-[10px] font-medium', guardChipClass(action.guard))}>
                  {action.guard}
                </span>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </div>
          </div>

          {action.target && (
            <div className="space-y-1">
              <p className="font-semibold text-muted-foreground uppercase tracking-wider text-[10px] mono">Target</p>
              <p className="mono text-foreground break-all">{action.target}</p>
            </div>
          )}

          <div className="space-y-1">
            <p className="font-semibold text-muted-foreground uppercase tracking-wider text-[10px] mono">Disposition</p>
            <p className="text-sev-high font-medium">Blocked · policy enforcement</p>
          </div>

          {action.detail && (
            <div className="space-y-1">
              <p className="font-semibold text-muted-foreground uppercase tracking-wider text-[10px] mono">Detail</p>
              <p className="text-muted-foreground leading-relaxed">{action.detail}</p>
            </div>
          )}

          <div className="rounded-md border border-border bg-secondary/40 px-3 py-2 text-[11px] text-muted-foreground">
            This is a read-only view. Blocked actions are policy-enforced — they cannot be approved or overridden from this pane.
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export function BlockedActionsPane() {
  const [detailAction, setDetailAction] = useState(null)
  const { portalState } = useStoreSlice((s) => ({ portalState: s.portalState }))

  const actions = blockedActions(portalState)
  const displayCount = Math.min(actions.length, 10)
  const displayActions = actions.slice(0, displayCount)
  const countLabel = actions.length > 9 ? '9+' : String(actions.length)

  return (
    <>
      <Card className="gap-0 p-0">
        <CardHeader className="flex flex-row items-center gap-2 border-b border-border p-4">
          <span aria-hidden className="flex size-7 shrink-0 items-center justify-center rounded-md border border-sev-high/30 bg-sev-high/10">
            <ShieldX className="size-[15px] text-sev-high" />
          </span>
          <CardTitle className="flex-1 text-sm font-semibold">Blocked actions</CardTitle>
          {actions.length > 0 && (
            <Badge variant="outline" className="tnum border-sev-high/40 text-sev-high">{countLabel}</Badge>
          )}
          <span className="mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
            Policy guards · Read-only
          </span>
        </CardHeader>

        <CardContent className="px-3 py-1" style={{ maxHeight: '288px', overflowY: 'auto' }}>
          {displayActions.length === 0 ? (
            <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
              <ShieldX className="size-4 text-muted-foreground/50" aria-hidden />
              No blocked actions — all tool calls are proceeding normally.
            </div>
          ) : (
            <div role="list" aria-label="Blocked actions">
              {displayActions.map((action, i) => (
                <div key={action.id} role="listitem" className={i > 0 ? 'border-t border-border/60' : ''}>
                  <BlockedRow action={action} onClick={setDetailAction} />
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <BlockedDetailModal action={detailAction} onClose={() => setDetailAction(null)} />
    </>
  )
}
