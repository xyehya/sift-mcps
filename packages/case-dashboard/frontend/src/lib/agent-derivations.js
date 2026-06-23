// ─────────────────────────────────────────────────────────────────────────
// Agent Command & Control — COMPOSED derivations (no JSX, no store, no network).
// The heavier selectors that fuse multiple `portalState` slices (+ chain /
// findings / case) into presentation-ready shapes for the Mission-Control
// Overview: the agent hero, the KPI tiles, the case synopsis and the HITL
// policy-gate taxonomy. The simple normalising selectors + presentation maps
// live in `agent-selectors.js`; both files re-export from the stable entry
// `agent-state.js`. See that entry / selectors for the `portalState` CONTRACT.
// ─────────────────────────────────────────────────────────────────────────

import { normStatus } from '@/components/findings/findings-utils'

import { AGENT_STATE } from '@/lib/agent-selectors'

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
      label: 'High confidence',
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

/**
 * agentSynopsis — the hero's case-driven synopsis sentence. DATA-DRIVEN (never a
 * hardcoded string): prefers the DB-authority `portalState.agent.headline`, then
 * composes from active-case metadata (incident type · severity · scope) joined
 * with the derived agent state, then finally the agent-state fallback. Always a
 * plain (escaped) string. `agent` is the output of deriveAgentState().
 */
export function agentSynopsis(portalState, activeCase, agent) {
  const headline = portalState?.agent?.headline
  if (headline) return headline
  if (activeCase) {
    const bits = []
    if (activeCase.incident_type) bits.push(String(activeCase.incident_type).replace(/_/g, ' '))
    if (activeCase.severity) bits.push(`${activeCase.severity} severity`)
    const systems = Array.isArray(activeCase.affected_systems) ? activeCase.affected_systems.length : 0
    if (systems) bits.push(`${systems} system${systems === 1 ? '' : 's'} in scope`)
    const lead = activeCase.title || activeCase.name || activeCase.case_id
    const ctx = bits.length ? ` — ${bits.join(' · ')}` : ''
    if (lead) return `${lead}${ctx}. ${agent?.headline ?? ''}`.trim()
  }
  return agent?.headline ?? ''
}
