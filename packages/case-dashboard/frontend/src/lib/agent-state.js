// ─────────────────────────────────────────────────────────────────────────
// Agent Command & Control — pure derivations + the store/api CONTRACT for the
// Mission-Control Overview (RUN-4b). No JSX, no store wiring, no network: these
// selectors map the EXISTING `portalState` store slice (DB authority, set via
// setPortalState) + chain/findings/delta into the agent hero, authorization
// queue and KPI tiles. The flat useStore surface is FROZEN — agent / gated-
// action / backend state therefore rides on `portalState` (an existing key),
// never a new top-level key. The dev mock (`src/_mock`) supplies a portalState
// matching this shape; a backend later populates the same field.
//
// CONTRACT — `portalState` (all fields optional; selectors degrade gracefully):
//   {
//     agent: {
//       state: 'awaiting-authorization' | 'working' | 'idle' | 'halt',
//       headline?: string,            // hero sentence (escaped text only)
//       metrics?: { records_parsed, findings_proposed, sources_fused },
//     },
//     gated_actions: [                // actions the agent CANNOT self-approve
//       { id, title, tool, icon: 'cpu'|'lock-open'|'shield'|'key-round',
//         risk: 'irreversible'|'reauth'|'elevated' }
//     ],
//     backends: { up, total, degraded: string[] },   // MCP backend health
//     evidence: { sealed, total },                    // custody coverage
//     iocs?: { total, hosts, accounts },
//     severity?: { high_open, high_awaiting },
//   }
// ─────────────────────────────────────────────────────────────────────────

import { normStatus } from '@/components/findings/findings-utils'

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

/**
 * deriveAgentState — the hero's agent identity + headline + stat strip. Prefers
 * the DB-authority `portalState.agent`; falls back to signals already in the
 * store (chain violation → halt, staged delta → awaiting-authorization) so the
 * hero is meaningful even before portalState loads.
 */
export function deriveAgentState(portalState, chainStatus, delta) {
  const queued = (portalState?.gated_actions ?? []).length || (delta ?? []).length
  let key = portalState?.agent?.state
  if (!key) {
    if (chainStatus?.status === 'violation') key = 'halt'
    else if (queued > 0) key = 'awaiting-authorization'
    else if (chainStatus) key = 'working'
    else key = 'idle'
  }
  const meta = AGENT_STATE[key] ?? AGENT_STATE.idle
  const m = portalState?.agent?.metrics ?? {}
  const headline =
    portalState?.agent?.headline ??
    (key === 'awaiting-authorization'
      ? `Agent has paused the pipeline. ${queued} gated ${queued === 1 ? 'action requires' : 'actions require'} your authorization before it can proceed.`
      : key === 'halt'
        ? 'Agent halted — evidence integrity must be restored before the investigation can continue.'
        : key === 'working'
          ? 'Agent is processing the autonomous investigation. No authorizations are pending.'
          : 'Agent is idle. Activate a case to begin the autonomous investigation.')
  return {
    key,
    label: meta.label,
    dot: meta.dot,
    text: meta.text,
    glow: meta.glow,
    queued,
    headline,
    metrics: [
      { key: 'records_parsed', value: m.records_parsed ?? 0, label: 'records parsed' },
      { key: 'findings_proposed', value: m.findings_proposed ?? 0, label: 'findings proposed' },
      { key: 'sources_fused', value: m.sources_fused ?? 0, label: 'sources fused' },
    ],
  }
}

/** Normalised gated-action list for the Authorization Required queue. */
export function gatedActions(portalState) {
  return (portalState?.gated_actions ?? []).map((a) => ({
    id: a.id ?? a.tool,
    title: a.title ?? a.tool,
    tool: a.tool ?? '',
    icon: a.icon ?? 'key-round',
    risk: a.risk ?? 'elevated',
  }))
}

/** Count HIGH-confidence findings (the "high severity" mission tile). */
function highSeverity(findings) {
  let open = 0
  let awaiting = 0
  for (const f of findings ?? []) {
    if ((f.confidence ?? '').toUpperCase() === 'HIGH') {
      open += 1
      if (normStatus(f) === 'draft') awaiting += 1
    }
  }
  return { open, awaiting }
}

/**
 * missionTiles — the four KPI tiles (Evidence sealed/total · High severity ·
 * IOCs · MCP backends up/total). Prefers portalState (DB authority) and falls
 * back to chain/findings/ioc slices. Returns presentation-ready rows with a
 * stable `key`, an icon key, a token tone class and a foot note.
 */
export function missionTiles(portalState, { chainStatus, findings, iocs } = {}) {
  const ev = portalState?.evidence ?? {}
  const sealed = ev.sealed ?? (chainStatus?.sealed_count ?? null)
  const evTotal = ev.total ?? (chainStatus?.total_count ?? null)
  const sev = portalState?.severity ?? highSeverity(findings)
  const io = portalState?.iocs ?? {}
  const iocTotal = io.total ?? (iocs ?? []).length
  const be = portalState?.backends ?? {}
  const beUp = be.up ?? null
  const beTotal = be.total ?? null
  const degraded = be.degraded ?? []

  return [
    {
      key: 'evidence',
      label: 'Evidence',
      icon: 'archive',
      tone: 'text-status-approved',
      value: sealed ?? '—',
      sub: evTotal != null ? `/${evTotal}` : '',
      foot: sealed != null && evTotal != null && sealed === evTotal ? 'Sealed · custody full' : 'Sealed of total',
    },
    {
      key: 'high',
      label: 'High severity',
      icon: 'flame',
      tone: 'text-sev-high',
      value: sev.open ?? 0,
      sub: 'open',
      foot: (sev.awaiting ?? 0) > 0 ? `${sev.awaiting} awaiting review` : 'all reviewed',
    },
    {
      key: 'iocs',
      label: 'IOCs',
      icon: 'crosshair',
      tone: 'text-sev-low',
      value: iocTotal,
      sub: '',
      foot: io.hosts != null || io.accounts != null ? `${io.hosts ?? 0} hosts · ${io.accounts ?? 0} accounts` : 'indicators tracked',
    },
    {
      key: 'backends',
      label: 'MCP backends',
      icon: 'server',
      tone: degraded.length > 0 ? 'text-sev-med' : 'text-status-approved',
      value: beUp ?? '—',
      sub: beTotal != null ? `/${beTotal} up` : '',
      foot: degraded.length > 0 ? `${degraded.length} degraded · ${degraded.join(', ')}` : 'all online',
    },
  ]
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
