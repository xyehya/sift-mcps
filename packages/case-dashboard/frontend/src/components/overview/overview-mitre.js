// ─────────────────────────────────────────────────────────────────────────
// Overview — MITRE ATT&CK model (RUN-4c). Pure derivations (no JSX, no store).
// Technique → tactic catalog + per-tactic token-class bundle so the panel reads
// "Lateral Movement › T1021.001" (grouped headers + colour-coded chips), not a
// flat pill list. Colour is supplementary to the always-present tactic LABEL and
// mono T-code (colour-not-only). Token classes are STATIC literals (JIT) — never
// orange (reserved for the agent). Unknown ids fall back to the `other` tactic.
// Re-exported from the stable entry `overview-metrics.js` (§7 util split).
// ─────────────────────────────────────────────────────────────────────────

/** Distinct MITRE ATT&CK technique ids across all findings, sorted. */
export function mitreTechniques(findings) {
  const ids = new Set()
  for (const f of findings ?? []) for (const id of f.mitre_ids ?? []) ids.add(id)
  return [...ids].sort()
}

/** Kill-chain order for stable tactic grouping. */
export const TACTIC_ORDER = [
  'initial-access', 'execution', 'persistence', 'privilege-escalation',
  'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
  'collection', 'command-and-control', 'exfiltration', 'impact', 'other',
]

/** tactic → label + static token-class bundle (text / dot / tint / ring). */
export const TACTIC_CLASS = {
  'initial-access': { label: 'Initial Access', text: 'text-sev-med', dot: 'bg-sev-med', tint: 'bg-sev-med/10', ring: 'border-sev-med/40' },
  'execution': { label: 'Execution', text: 'text-sev-low', dot: 'bg-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/40' },
  'persistence': { label: 'Persistence', text: 'text-sev-low', dot: 'bg-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/40' }, /* TODO: was sev-spec; remapped to sev-low (steel) — sev-spec removed in token re-port */
  'privilege-escalation': { label: 'Privilege Escalation', text: 'text-sev-high', dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  'defense-evasion': { label: 'Defense Evasion', text: 'text-status-staged', dot: 'bg-status-staged', tint: 'bg-status-staged/10', ring: 'border-status-staged/40' },
  'credential-access': { label: 'Credential Access', text: 'text-sev-high', dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  'discovery': { label: 'Discovery', text: 'text-sev-low', dot: 'bg-sev-low', tint: 'bg-sev-low/10', ring: 'border-sev-low/40' },
  'lateral-movement': { label: 'Lateral Movement', text: 'text-sev-med', dot: 'bg-sev-med', tint: 'bg-sev-med/10', ring: 'border-sev-med/40' },
  'collection': { label: 'Collection', text: 'text-status-approved', dot: 'bg-status-approved', tint: 'bg-status-approved/10', ring: 'border-status-approved/40' },
  'command-and-control': { label: 'Command and Control', text: 'text-sev-high', dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  'exfiltration': { label: 'Exfiltration', text: 'text-sev-high', dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'border-sev-high/40' },
  'impact': { label: 'Impact', text: 'text-destructive', dot: 'bg-destructive', tint: 'bg-destructive/10', ring: 'border-destructive/40' },
  'other': { label: 'Other', text: 'text-muted-foreground', dot: 'bg-muted-foreground', tint: 'bg-secondary', ring: 'border-border' },
}

export function tacticMeta(tactic) {
  return TACTIC_CLASS[tactic] ?? TACTIC_CLASS.other
}

/** Curated technique → { name, tactic } catalog (the mock's technique→tactic data). */
export const MITRE_CATALOG = {
  'T1021': { name: 'Remote Services', tactic: 'lateral-movement' },
  'T1021.001': { name: 'Remote Services: RDP', tactic: 'lateral-movement' },
  'T1078': { name: 'Valid Accounts', tactic: 'privilege-escalation' },
  'T1078.002': { name: 'Valid Accounts: Domain Accounts', tactic: 'privilege-escalation' },
  'T1053': { name: 'Scheduled Task/Job', tactic: 'persistence' },
  'T1053.005': { name: 'Scheduled Task', tactic: 'persistence' },
  'T1574': { name: 'Hijack Execution Flow', tactic: 'defense-evasion' },
  'T1574.002': { name: 'DLL Side-Loading', tactic: 'defense-evasion' },
  'T1039': { name: 'Data from Network Shared Drive', tactic: 'collection' },
  'T1530': { name: 'Data from Cloud Storage', tactic: 'collection' },
  'T1071': { name: 'Application Layer Protocol', tactic: 'command-and-control' },
  'T1071.001': { name: 'Web Protocols', tactic: 'command-and-control' },
  'T1070': { name: 'Indicator Removal', tactic: 'defense-evasion' },
  'T1070.001': { name: 'Clear Windows Event Logs', tactic: 'defense-evasion' },
  'T1059': { name: 'Command and Scripting Interpreter', tactic: 'execution' },
  'T1059.001': { name: 'PowerShell', tactic: 'execution' },
  'T1486': { name: 'Data Encrypted for Impact', tactic: 'impact' },
  'T1003': { name: 'OS Credential Dumping', tactic: 'credential-access' },
}

/** Resolve a technique id → { id, name, tactic } (sub-technique falls back to base). */
export function techniqueMeta(id) {
  const hit = MITRE_CATALOG[id] ?? MITRE_CATALOG[String(id).split('.')[0]]
  return { id, name: hit?.name ?? null, tactic: hit?.tactic ?? 'other' }
}

/**
 * mitreByTactic — distinct techniques across findings, grouped under their ATT&CK
 * tactic in kill-chain order. Each technique records the finding ids that cite it
 * (for the detail side-panel). Returns `[{ tactic, meta, techniques:[{ id, name,
 * findingIds }] }]`, empty tactics omitted.
 */
export function mitreByTactic(findings) {
  const byId = new Map()
  for (const f of findings ?? []) {
    for (const id of f.mitre_ids ?? []) {
      if (!byId.has(id)) byId.set(id, { ...techniqueMeta(id), findingIds: [] })
      byId.get(id).findingIds.push(f.id)
    }
  }
  const groups = new Map()
  for (const t of byId.values()) {
    if (!groups.has(t.tactic)) groups.set(t.tactic, [])
    groups.get(t.tactic).push(t)
  }
  return TACTIC_ORDER.filter((tac) => groups.has(tac)).map((tactic) => ({
    tactic,
    meta: tacticMeta(tactic),
    techniques: groups.get(tactic).sort((a, b) => a.id.localeCompare(b.id)),
  }))
}
