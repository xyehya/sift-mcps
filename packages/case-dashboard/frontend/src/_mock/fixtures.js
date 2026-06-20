// ─────────────────────────────────────────────────────────────────────────
// DEV-ONLY demo fixtures for visual sign-off (Overview + Findings populated).
// This module is loaded ONLY behind `import.meta.env.DEV && ?mock` via a
// dynamic import(), so production builds tree-shake it out entirely. The
// MOCK_MARKER string is asserted absent from the prod dist by the gate.
// NOTHING here is real case data — it is synthetic and self-evidently demo.
// ─────────────────────────────────────────────────────────────────────────

export const MOCK_MARKER = '__SIFT_MOCK_FIXTURES_DEMO__'

const now = Date.now()
const H = 3600 * 1000
const D = 24 * H
const iso = (msAgo) => new Date(now - msAgo).toISOString()

const FINDINGS = [
  {
    id: 'F-001',
    type: 'finding',
    title: 'RDP lateral movement from WS-FINANCE-03 to DC-01',
    status: 'draft',
    confidence: 'HIGH',
    host: 'WS-FINANCE-03',
    affected_account: 'svc-backup',
    event_timestamp: iso(2 * H),
    modified_at: iso(1.5 * H),
    content_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
    description: 'Authenticated RDP session originating from a finance workstation pivoted into the primary domain controller using a service account.',
    observation: 'EVTX 4624 logon type 10 from 10.4.2.31 → DC-01 at 02:14 UTC using svc-backup.',
    interpretation: 'Service account is not expected to perform interactive RDP. Consistent with hands-on-keyboard lateral movement.',
    confidence_justification: 'Corroborated by firewall flow logs and the absence of a scheduled-task context for svc-backup.',
    mitre_ids: ['T1021.001', 'T1078.002'],
    iocs: ['10.4.2.31', 'svc-backup'],
    tags: ['lateral-movement', 'priority'],
    audit_ids: ['AUD-1024'],
    related_findings: ['F-002'],
    artifacts: [
      { source: 'Security.evtx', extraction: 'EvtxECmd → 4624', content: 'LogonType=10\nIpAddress=10.4.2.31\nTargetUser=svc-backup' },
    ],
    verification: 'confirmed',
    provenance: 'MCP',
  },
  {
    id: 'F-002',
    type: 'finding',
    title: 'Suspicious scheduled task "UpdateSync" persisting beacon',
    status: 'draft',
    confidence: 'MEDIUM',
    host: 'DC-01',
    event_timestamp: iso(5 * H),
    modified_at: iso(4 * H),
    content_hash: 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7',
    description: 'A scheduled task named UpdateSync launches a signed binary that side-loads an unsigned DLL.',
    observation: 'schtasks output shows UpdateSync running rundll32 against C:\\ProgramData\\sync.dll every 30 min.',
    interpretation: 'DLL side-loading via a benign-looking task is a common persistence + C2 keep-alive technique.',
    confidence_justification: 'DLL is unsigned and recently created; network beacon not yet confirmed.',
    mitre_ids: ['T1053.005', 'T1574.002'],
    iocs: ['C:\\ProgramData\\sync.dll'],
    tags: ['persistence'],
    audit_ids: ['AUD-1031'],
    supporting_commands: [{ command: 'schtasks /query /tn UpdateSync /v', output_excerpt: 'Task To Run: rundll32 C:\\ProgramData\\sync.dll,Start' }],
    verification: 'draft',
    provenance: 'SHELL',
  },
  {
    id: 'F-003',
    type: 'finding',
    title: 'Bulk file access to \\\\FS-01\\HR-Confidential',
    status: 'approved',
    confidence: 'HIGH',
    host: 'FS-01',
    affected_account: 'm.reyes',
    event_timestamp: iso(1 * D),
    modified_at: iso(20 * H),
    approved_by: 'a.morgan',
    approved_at: iso(18 * H),
    content_hash: 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8',
    description: '4,200 files read from the HR confidential share within 11 minutes by a single account.',
    observation: 'File audit events 5145 show sequential reads of HR-Confidential by m.reyes.',
    interpretation: 'Volume and velocity are inconsistent with normal HR workflow; likely staging for exfiltration.',
    confidence_justification: 'Access pattern + off-hours timing + subsequent archive creation.',
    mitre_ids: ['T1039', 'T1530'],
    iocs: ['m.reyes'],
    tags: ['collection', 'exfil-risk'],
    verification: 'confirmed',
    provenance: 'MCP',
  },
  {
    id: 'F-004',
    type: 'finding',
    title: 'Outbound HTTPS beacon to 185.99.x.x every 60s',
    status: 'draft',
    confidence: 'LOW',
    host: 'WS-FINANCE-03',
    event_timestamp: iso(3 * H),
    modified_at: iso(2.5 * H),
    content_hash: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9',
    description: 'Regular-interval TLS connections to a low-reputation host.',
    observation: 'Zeek conn.log shows 60s-periodic 443/tcp to 185.99.12.44.',
    interpretation: 'Periodicity suggests automated beaconing; destination reputation is poor but unconfirmed C2.',
    confidence_justification: 'Beacon cadence is suggestive but the destination is not yet attributed.',
    mitre_ids: ['T1071.001'],
    iocs: ['185.99.12.44'],
    tags: ['c2'],
    verification: 'draft',
    provenance: 'MCP',
  },
  {
    id: 'F-005',
    type: 'finding',
    title: 'Cleared Security event log on DC-01',
    status: 'rejected',
    confidence: 'MEDIUM',
    host: 'DC-01',
    event_timestamp: iso(2 * D),
    modified_at: iso(1.2 * D),
    rejected_by: 'a.morgan',
    rejected_at: iso(1.1 * D),
    rejection_reason: 'Correlated to a sanctioned maintenance window; benign.',
    description: 'Event 1102 indicates the Security log was cleared.',
    observation: 'Event 1102 at 23:50 UTC by account dc-admin.',
    interpretation: 'Log clearing can hide activity, but timing matched an approved patch window.',
    confidence_justification: 'Change ticket CHG-8841 covers this maintenance.',
    mitre_ids: ['T1070.001'],
    iocs: [],
    tags: ['anti-forensics'],
    verification: 'draft',
    provenance: 'HOOK',
  },
  {
    id: 'F-006',
    type: 'finding',
    title: 'Speculative: PowerShell encoded command on WS-MKT-12',
    status: 'draft',
    confidence: 'SPECULATIVE',
    host: 'WS-MKT-12',
    event_timestamp: iso(6 * H),
    modified_at: iso(6 * H),
    content_hash: 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
    description: 'A single base64-encoded PowerShell invocation observed without follow-on activity.',
    observation: '4104 script block shows -enc with a benign decoded payload.',
    interpretation: 'Possibly admin tooling; flagged for review pending more context.',
    confidence_justification: 'Decoded content appears benign; included for completeness.',
    mitre_ids: ['T1059.001'],
    iocs: [],
    tags: [],
    verification: 'draft',
    provenance: 'MCP',
  },
]

const DELTA = [
  { id: 'F-001', type: 'finding', action: 'approve', content_hash_at_review: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', modifications: {} },
  {
    id: 'F-002',
    type: 'finding',
    action: 'edit',
    content_hash_at_review: 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7',
    modifications: { confidence: { original: 'MEDIUM', modified: 'HIGH' } },
  },
]

const SUMMARY = {
  findings: { total: FINDINGS.length, by_status: { draft: 4, approved: 1, rejected: 1 } },
  todos: { open: 3 },
}

const TIMELINE = [
  { id: 'E-1', timestamp: iso(2 * H + 20 * 60 * 1000), type: 'logon', description: 'RDP 4624 logon type 10 from 10.4.2.31', finding_refs: ['F-001'] },
  { id: 'E-2', timestamp: iso(2 * H), type: 'logon', description: 'Service account svc-backup authenticated to DC-01', finding_refs: ['F-001'] },
  { id: 'E-3', timestamp: iso(2 * H - 30 * 60 * 1000), type: 'process', description: 'cmd.exe spawned by mstsc on DC-01' },
]

const CHAIN_STATUS = { status: 'ok', manifest_version: 3, hmac_verify_needed: false, write_protected: true }

// Agent Command & Control state (DB-authority `portalState` contract — see
// lib/agent-state.js). Agent is paused awaiting authorization so the Mission
// Control hero + Authorization Required queue are populated for sign-off.
const PORTAL_STATE = {
  agent: {
    state: 'awaiting-authorization',
    // Case-driven synopsis (RUN-4c #40): describes the investigation, not the
    // auth queue (that lives in the Authorization Required panel). Long enough to
    // exercise the hero's Show-more truncation.
    headline:
      'Reconstructed a hands-on-keyboard intrusion across NORTHWIND: RDP lateral movement from WS-FINANCE-03 into the DC-01 domain controller, a "UpdateSync" persistence task side-loading an unsigned DLL, and bulk staging of HR-confidential records on FS-01. 47 findings proposed from 3 fused evidence sources; the highest-severity chain is corroborated by firewall flow logs.',
    metrics: { records_parsed: 1284402, findings_proposed: 47, sources_fused: 3 },
  },
  gated_actions: [
    { id: 'ga-1', title: 'Acquire volatile memory — WS-FINANCE-03', tool: 'mcp:acquire.memory', icon: 'cpu', risk: 'irreversible' },
    { id: 'ga-2', title: 'Unseal EV-014 for re-hash', tool: 'mcp:evidence.unseal', icon: 'lock-open', risk: 'reauth' },
    { id: 'ga-3', title: 'Quarantine payload.dll → isolated vault', tool: 'mcp:fs.quarantine', icon: 'shield', risk: 'elevated' },
  ],
  backends: { up: 7, total: 8, degraded: ['yara'] },
  // A NAMED system/tool blocker (not a policy gate) — the Authorization Required
  // panel surfaces this with a distinct treatment (RUN-4c HITL taxonomy).
  system_blockers: [
    {
      id: 'sb-yara',
      name: 'yara',
      tool: 'mcp:yara.scan',
      detail: 'YARA scan backend degraded — rule compilation is failing; signature matching is unavailable until the backend recovers.',
    },
  ],
  // sealed < total ⇒ a derived "evidence custody not fully sealed" policy gate.
  evidence: { sealed: 12, total: 14 },
  iocs: { total: 23, hosts: 9, accounts: 31 },
  severity: { open: 6, awaiting: 3 },
}

const ACTIVE_CASE = {
  case_id: 'CASE-2026-0410',
  name: 'NORTHWIND',
  title: 'NORTHWIND intrusion investigation',
  status: 'active',
  examiner: 'a.morgan',
  created: iso(3 * D),
  incident_type: 'unauthorized_access',
  severity: 'high',
  tlp: 'AMBER',
  description: 'Suspected hands-on-keyboard intrusion with lateral movement into the domain controller and staging of HR data.',
  affected_systems: ['DC-01', 'WS-FINANCE-03', 'FS-01'],
  affected_accounts: ['svc-backup', 'm.reyes'],
  occurred_at: iso(3 * D),
  detected_at: iso(1.5 * D),
  reported_at: iso(1 * D),
  tags: ['ransomware-precursor', 'priority'],
  impact_summary: 'Potential exposure of HR confidential records; domain controller integrity under review.',
}

const REPORTS = [
  { id: 'rpt-7f3a21', profile: 'executive', examiner: 'a.morgan', created_at: iso(12 * H) },
  { id: 'rpt-9c0b54', profile: 'technical', examiner: 'a.morgan', created_at: iso(30 * H) },
]

const IOCS = [
  { id: 'ioc-1', type: 'ip', value: '185.99.12.44' },
  { id: 'ioc-2', type: 'account', value: 'svc-backup' },
]

const USER = { examiner: 'a.morgan', role: 'examiner' }

// Multi-case switcher demo: active / inactive / sealed lifecycle badges.
const CASES = [
  { id: 'CASE-2026-0410', name: 'NORTHWIND', status: 'active', active: true },
  { id: 'CASE-2026-0388', name: 'REDWING', status: 'inactive', active: false },
  { id: 'CASE-2026-0351', name: 'BLACKSMITH', status: 'sealed', active: false },
]

export const mockState = {
  user: USER,
  activeCase: ACTIVE_CASE,
  cases: CASES,
  findings: FINDINGS,
  delta: DELTA,
  summary: SUMMARY,
  timeline: TIMELINE,
  chainStatus: CHAIN_STATUS,
  portalState: PORTAL_STATE,
  reports: REPORTS,
  iocs: IOCS,
  isLoading: false,
  lastSync: now,
}
