// ─────────────────────────────────────────────────────────────────────────
// Agent Command & Control — STABLE public entry (AGENTS §2/§11: all agent state
// logic lives here ONLY; this module path is imported across the app and must
// not break). Pure derivations + the store/api CONTRACT for the Mission-Control
// Overview (RUN-4b). No JSX, no store wiring, no network: these selectors map
// the EXISTING `portalState` store slice (DB authority, set via setPortalState)
// + chain/findings/delta into the agent hero, authorization queue and KPI tiles.
// The flat useStore surface is frozen by test; agent / gated-action / backend
// state rides on `portalState`, while the B1 audit tail uses `agentActivity`.
// The dev mock (`src/_mock`) supplies a portalState matching this shape; a
// backend later populates the same field.
//
// Implementation is split (§7 util ceiling) into two sibling files, both
// re-exported below so this entry remains the single import surface:
//   · agent-selectors.js   — presentation maps + simple normalising selectors
//                            + the HITL gate taxonomy (AGENT_STATE, RISK_CLASS,
//                             riskMeta, gatedActions, blockedActions, policyGates,
//                             systemBlockers, statusCounts)
//   · agent-derivations.js — composed derivations (deriveAgentState,
//                             missionTiles, agentSynopsis)
//
// CONTRACT — `portalState` (all fields optional; selectors degrade gracefully):
//   {
//     agent: {
//       state: 'awaiting-authorization' | 'working' | 'idle' | 'halt',
//       headline?: string,            // hero sentence (escaped text only)
//       metrics?: { findings_proposed },
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

export {
  AGENT_STATE,
  RISK_CLASS,
  riskMeta,
  gatedActions,
  blockedActions,
  policyGates,
  systemBlockers,
  statusCounts,
} from '@/lib/agent-selectors'

export {
  deriveAgentState,
  missionTiles,
  agentSynopsis,
} from '@/lib/agent-derivations'
