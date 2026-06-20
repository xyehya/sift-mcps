import { Cpu, KeyRound, LockOpen, Scale, ServerCrash, ShieldAlert, ShieldCheck } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { gatedActions, policyGates, systemBlockers, riskMeta } from '@/lib/agent-state'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

// ─────────────────────────────────────────────────────────────────────────
// AuthorizationQueue — the page hero, modelling the HITL gate as THREE clearly
// separated concerns (RUN-4c):
//   1. POLICY GATES — the only two conditions that policy-pause the agent (case
//      not active · evidence integrity compromised/unsealed). Derived, max two.
//   2. GATED ACTIONS — operator-authorizable MCP actions the agent queued and
//      cannot self-approve (each carries a risk chip + "Review & authorize").
//   3. SYSTEM / TOOL BLOCKERS — backend/tool failures (e.g. degraded `yara`).
//      Distinct visual treatment (dashed amber) + a "system issue, NOT a policy
//      gate" label so the examiner never confuses the two.
// All three derive from the EXISTING portalState slice + case/chain (selectors in
// lib/agent-state.js); the mock supplies policy gates AND a system blocker. NO
// fabricated security claim — "Review & authorize" surfaces a step-up notice; it
// does not perform a real authorization.
// ─────────────────────────────────────────────────────────────────────────

const ACTION_ICONS = { cpu: Cpu, 'lock-open': LockOpen, shield: ShieldCheck, 'key-round': KeyRound }
const GATE_ICONS = { case: Scale, evidence: ShieldAlert }

/** Section heading inside the panel body (small, mono, uppercase). */
function GroupLabel({ children, tone = 'text-muted-foreground' }) {
  return <p className={cn('mono px-1 pb-1 pt-3 text-[10px] font-semibold uppercase tracking-[0.14em]', tone)}>{children}</p>
}

/** A policy gate — a hard pause reason. Tinted by kind; carries a resolve link. */
function GateRow({ gate, onResolve, divided }) {
  const Icon = GATE_ICONS[gate.kind] ?? ShieldAlert
  return (
    <div className={cn('flex items-start gap-3 py-3', divided && 'border-t border-border')}>
      <span aria-hidden className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-primary/40 bg-primary/10">
        <Icon className="size-[18px] text-primary" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-foreground">{gate.title}</span>
          <Badge variant="outline" className="border-primary/40 text-[10px] text-primary">Policy gate</Badge>
        </div>
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{gate.detail}</p>
      </div>
      {gate.tab && (
        <Button type="button" variant="outline" size="sm" onClick={() => onResolve(gate)} className="shrink-0">
          Resolve
        </Button>
      )}
    </div>
  )
}

/** A gated action — operator-authorizable, risk-chipped. */
function ActionRow({ action, onAuthorize, divided }) {
  const Icon = ACTION_ICONS[action.icon] ?? KeyRound
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
      <Button type="button" variant="outline" size="sm" onClick={() => onAuthorize(action)} className="shrink-0 gap-1.5">
        <KeyRound className="size-3.5" aria-hidden />
        Review &amp; authorize
      </Button>
    </div>
  )
}

/** A system blocker — DISTINCT dashed-amber treatment; not operator-authorizable. */
function BlockerRow({ blocker, onView, divided }) {
  return (
    <div className={cn('flex items-start gap-3 py-3', divided && 'border-t border-dashed border-sev-med/40')}>
      <span aria-hidden className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-dashed border-sev-med/50 bg-sev-med/10">
        <ServerCrash className="size-[18px] text-sev-med" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="mono text-sm font-medium text-foreground">{blocker.name}</span>
          <Badge variant="outline" className="border-dashed border-sev-med/50 text-[10px] text-sev-med">System issue · not a policy gate</Badge>
        </div>
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{blocker.detail}</p>
      </div>
      <Button type="button" variant="ghost" size="sm" onClick={onView} className="shrink-0 text-muted-foreground">
        Backends
      </Button>
    </div>
  )
}

export function AuthorizationQueue() {
  const { portalState, activeCase, chainStatus, addToast, setActiveTab } = useStoreSlice((s) => ({
    portalState: s.portalState,
    activeCase: s.activeCase,
    chainStatus: s.chainStatus,
    addToast: s.addToast,
    setActiveTab: s.setActiveTab,
  }))

  const gates = policyGates(portalState, activeCase, chainStatus)
  const actions = gatedActions(portalState)
  const blockers = systemBlockers(portalState)
  const authCount = gates.length + actions.length

  function onAuthorize(action) {
    addToast(`Step-up authorization required for ${action.tool} — re-authenticate to proceed.`, 'warn')
  }

  const isEmpty = authCount === 0 && blockers.length === 0

  return (
    <Card className="gap-0 p-0">
      <CardHeader className="flex flex-row items-center justify-between gap-2 border-b border-border p-4">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="size-[18px] text-primary" aria-hidden />
          <CardTitle className="text-sm font-semibold">Authorization required</CardTitle>
          {authCount > 0 && <Badge className="tnum">{authCount}</Badge>}
        </div>
        <span className="mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">Agent cannot self-approve</span>
      </CardHeader>
      <CardContent className="px-4 py-1">
        {isEmpty ? (
          <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
            <ShieldCheck className="size-4 text-status-approved" aria-hidden />
            No policy gates, gated actions or system blockers — the agent is clear to proceed.
          </div>
        ) : (
          <>
            {gates.length > 0 && (
              <section aria-label="Policy gates">
                <GroupLabel tone="text-primary">Policy gates · agent paused</GroupLabel>
                {gates.map((g, i) => (
                  <GateRow key={g.id} gate={g} divided={i > 0} onResolve={(gate) => navigateToTab(setActiveTab, gate.tab)} />
                ))}
              </section>
            )}

            {actions.length > 0 && (
              <section aria-label="Gated actions">
                <GroupLabel>Gated actions · awaiting authorization</GroupLabel>
                {actions.map((a, i) => (
                  <ActionRow key={a.id} action={a} onAuthorize={onAuthorize} divided={i > 0} />
                ))}
              </section>
            )}

            {blockers.length > 0 && (
              <section aria-label="System blockers">
                <GroupLabel tone="text-sev-med">System / tool blockers</GroupLabel>
                {blockers.map((b, i) => (
                  <BlockerRow key={b.id} blocker={b} divided={i > 0} onView={() => navigateToTab(setActiveTab, 'backends')} />
                ))}
              </section>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
