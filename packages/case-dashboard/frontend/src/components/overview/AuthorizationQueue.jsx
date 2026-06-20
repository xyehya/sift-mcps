import { Cpu, KeyRound, LockOpen, ShieldAlert, ShieldCheck } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { gatedActions, riskMeta } from '@/lib/agent-state'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

// ─────────────────────────────────────────────────────────────────────────
// AuthorizationQueue — the page hero: gated MCP actions the agent CANNOT
// self-approve. Each row shows the tool (mono), a risk chip, and a "Review &
// authorize" control. This is the human-in-the-loop gate; the agent has paused
// until the operator acts. The list is read from the EXISTING portalState slice
// (contract in lib/agent-state.js). "Review & authorize" surfaces an explicit
// notice — the real step-up authorization flow is backend wiring (Phase 1+); we
// make NO fabricated security claim here.
// ─────────────────────────────────────────────────────────────────────────

const ICONS = { cpu: Cpu, 'lock-open': LockOpen, shield: ShieldCheck, 'key-round': KeyRound }

function ActionRow({ action, onAuthorize, divided }) {
  const Icon = ICONS[action.icon] ?? KeyRound
  const risk = riskMeta(action.risk)
  return (
    <div className={cn('flex items-center gap-3 py-3', divided && 'border-t border-border')}>
      <span aria-hidden className={cn('flex size-9 shrink-0 items-center justify-center rounded-lg border', risk.ring, risk.tint)}>
        <Icon className={cn('size-[18px]', risk.text)} />
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium text-foreground">{action.title}</div>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <span className="mono text-[11px] text-muted-foreground">{action.tool}</span>
          <Badge variant="outline" className={cn('text-[10px]', risk.text, risk.ring)}>
            {risk.label}
          </Badge>
        </div>
      </div>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => onAuthorize(action)}
        className="shrink-0 gap-1.5"
      >
        <KeyRound className="size-3.5" aria-hidden />
        Review &amp; authorize
      </Button>
    </div>
  )
}

export function AuthorizationQueue() {
  const { portalState, addToast } = useStoreSlice((s) => ({ portalState: s.portalState, addToast: s.addToast }))
  const actions = gatedActions(portalState)

  function onAuthorize(action) {
    addToast(`Step-up authorization required for ${action.tool} — re-authenticate to proceed.`, 'warn')
  }

  return (
    <Card className="gap-0 p-0">
      <CardHeader className="flex flex-row items-center justify-between gap-2 border-b border-border p-4">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="size-[18px] text-primary" aria-hidden />
          <CardTitle className="text-sm font-semibold">Authorization required</CardTitle>
          {actions.length > 0 && (
            <Badge className="tnum">{actions.length}</Badge>
          )}
        </div>
        <span className="mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">Agent cannot self-approve</span>
      </CardHeader>
      <CardContent className="px-4 py-1">
        {actions.length === 0 ? (
          <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
            <ShieldCheck className="size-4 text-status-approved" aria-hidden />
            No actions awaiting authorization — the agent is clear to proceed.
          </div>
        ) : (
          actions.map((a, i) => (
            <ActionRow key={a.id} action={a} onAuthorize={onAuthorize} divided={i > 0} />
          ))
        )}
      </CardContent>
    </Card>
  )
}
