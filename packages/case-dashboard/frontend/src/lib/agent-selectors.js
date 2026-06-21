// ─────────────────────────────────────────────────────────────────────────
// Agent Command & Control — pure SELECTORS + presentation maps (no JSX, no
// store wiring, no network). Static literal token-class bundles (Tailwind JIT)
// plus the simple normalising selectors that flatten `portalState` slices into
// list/count shapes. The heavier composed derivations (hero state, KPI tiles,
// policy gates) live in `agent-derivations.js`; both are re-exported from the
// stable entry `agent-state.js`. The flat useStore surface is FROZEN — agent /
// gated-action / backend state rides on `portalState` (an existing key).
// ─────────────────────────────────────────────────────────────────────────

/** Canonical agent states (keys) + their presentation. Static literal classes. */
export const AGENT_STATE = {
  'awaiting-authorization': {
    label: 'Awaiting authorization',
    dot: 'bg-primary',
    text: 'text-primary',
    glow: true,
  },
  working: { label: 'Working', dot: 'bg-status-approved', text: 'text-status-approved', glow: false },
  idle: { label: 'Idle', dot: 'bg-muted-foreground', text: 'text-muted-foreground', glow: false },
  halt: { label: 'Integrity halt', dot: 'bg-destructive', text: 'text-destructive', glow: false },
}

/** Gated-action risk → static token-class bundle + default chip label. */
export const RISK_CLASS = {
  irreversible: { label: 'Irreversible · one-shot', text: 'text-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  reauth: { label: 'Requires re-auth', text: 'text-sev-med', tint: 'bg-sev-med/10', ring: 'border-sev-med/40' },
  elevated: { label: 'Elevated · reversible', text: 'text-status-staged', tint: 'bg-status-staged/10', ring: 'border-status-staged/40' },
}

export function riskMeta(risk) {
  return RISK_CLASS[risk] ?? { label: 'Gated action', text: 'text-muted-foreground', tint: 'bg-secondary', ring: 'border-border' }
}

/** Normalised gated-action list — kept for backward compat with AuthorizationQueue. */
export function gatedActions(portalState) {
  return (portalState?.gated_actions ?? []).map((a) => ({
    id: a.id ?? a.tool,
    title: a.title ?? a.tool,
    tool: a.tool ?? '',
    icon: a.icon ?? 'key-round',
    risk: a.risk ?? 'elevated',
  }))
}

/**
 * blockedActions — the read-only blocked-tool-calls list for the
 * BlockedActionsPane (model-shift §3: agent runs autonomously; blocked calls
 * are surfaced for AWARENESS, not approval). Normalises from the
 * `portalState.blocked_actions` field; also falls back to `gated_actions` for
 * backwards compat so the mock data can supply either field. Each entry:
 * { id, title, tool, guard, target, timestamp, detail }.
 */
export function blockedActions(portalState) {
  const src = portalState?.blocked_actions ?? portalState?.gated_actions ?? []
  return src.map((a, i) => ({
    id: a.id ?? a.tool ?? `ba-${i}`,
    title: a.title ?? a.tool ?? 'Blocked tool call',
    tool: a.tool ?? '',
    guard: a.guard ?? guardFromRisk(a.risk),
    target: a.target ?? '',
    timestamp: a.timestamp ?? '',
    detail: a.detail ?? '',
  }))
}

/** Derive a human-readable guard label from a risk field (compat with old shape). */
function guardFromRisk(risk) {
  if (!risk) return ''
  if (risk === 'irreversible') return 'Integrity guard'
  if (risk === 'reauth') return 'Custody guard'
  if (risk === 'elevated') return 'Acquisition guard'
  return ''
}

// ── HITL gate taxonomy (RUN-4c) ──────────────────────────────────────────────
// The Authorization-Required panel separates THREE concerns, never conflating
// them: (1) POLICY GATES — the only two conditions that policy-pause the agent;
// (2) the gated ACTIONS the agent queued (gatedActions, above); (3) SYSTEM
// BLOCKERS — backend/tool failures that are NOT policy decisions (systemBlockers,
// below). Encoded as derived selectors so the panel + any future surface agree.
// All degrade safely when inputs are null.

/** A case is "active" only when its lifecycle status says so. */
function caseIsActive(activeCase) {
  if (!activeCase) return true // no case loaded yet → don't fabricate a gate
  const s = (activeCase.status || (activeCase.active ? 'active' : 'inactive')).toLowerCase()
  return s === 'active'
}

/**
 * policyGates — EXACTLY the two policy-gate triggers, derived, max two entries:
 *   (1) the case is not in an active state, and
 *   (2) evidence integrity is compromised (chain violation/tampered) OR custody
 *       is not fully sealed (unsealed items present).
 * Nothing else is a policy gate. Each entry: { id, kind, title, detail, tab }.
 */
export function policyGates(portalState, activeCase, chainStatus) {
  const gates = []
  if (activeCase && !caseIsActive(activeCase)) {
    const s = (activeCase.status || (activeCase.active ? 'active' : 'inactive')).toLowerCase()
    gates.push({
      id: 'gate-case',
      kind: 'case',
      title: 'Case is not in an active state',
      detail: `Case status is “${s}”. Re-activate the case before the agent can act.`,
      tab: 'overview',
    })
  }
  const ev = portalState?.evidence ?? {}
  const sealStatus = (chainStatus?.seal_status || chainStatus?.status || '').toLowerCase()
  const violation = sealStatus === 'violation' || sealStatus === 'tampered'
  const unsealed = ev.sealed != null && ev.total != null ? Math.max(0, ev.total - ev.sealed) : 0
  if (violation) {
    gates.push({
      id: 'gate-evidence',
      kind: 'evidence',
      title: 'Evidence integrity compromised',
      detail: 'Chain-of-custody verification failed. Restore integrity before the agent can proceed.',
      tab: 'evidence',
    })
  } else if (unsealed > 0) {
    gates.push({
      id: 'gate-evidence',
      kind: 'evidence',
      title: 'Evidence custody not fully sealed',
      detail: `${unsealed} of ${ev.total} evidence item${unsealed === 1 ? '' : 's'} unsealed — re-seal or authorize custody to proceed.`,
      tab: 'evidence',
    })
  }
  return gates
}

/**
 * systemBlockers — NAMED backend/tool failures (NOT policy gates). Prefers an
 * explicit `portalState.system_blockers` ([{name, tool, detail}]) and otherwise
 * derives from `backends.degraded` names. Each entry carries a NAME + a plain
 * detail string so the panel can render a distinct, clearly-labelled "system
 * issue" treatment separate from the policy auth-gates.
 */
export function systemBlockers(portalState) {
  const explicit = portalState?.system_blockers
  if (Array.isArray(explicit) && explicit.length > 0) {
    return explicit.map((b, i) => ({
      id: b.id ?? b.name ?? `sysblock-${i}`,
      name: b.name ?? b.tool ?? 'backend',
      tool: b.tool ?? '',
      detail: b.detail ?? 'Backend tool unavailable.',
    }))
  }
  const degraded = portalState?.backends?.degraded ?? []
  return degraded.map((name) => ({
    id: `sysblock-${name}`,
    name,
    tool: '',
    detail: `${name} backend degraded or unavailable — tools that depend on it may fail.`,
  }))
}

/** Custody + backend counts for the StatusBar tail (SEALED X/Y · MCP X/Y). */
export function statusCounts(portalState, chainStatus) {
  const ev = portalState?.evidence ?? {}
  const be = portalState?.backends ?? {}
  return {
    sealed: ev.sealed ?? chainStatus?.sealed_count ?? null,
    evidenceTotal: ev.total ?? chainStatus?.total_count ?? null,
    backendsUp: be.up ?? null,
    backendsTotal: be.total ?? null,
    degraded: (be.degraded ?? []).length,
  }
}
