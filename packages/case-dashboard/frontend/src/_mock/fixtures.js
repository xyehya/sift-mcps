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
    approved_by: 'e.varga',
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
    rejected_by: 'e.varga',
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
    title: 'PowerShell encoded command on WS-MKT-12',
    status: 'draft',
    confidence: 'MEDIUM',
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
// lib/agent-state.js). Agent runs autonomously; blocked_actions populates the
// read-only BlockedActionsPane for awareness. Blocked-actions timestamps:
const _fmtTs = (msAgo) => {
  const m = Math.round(msAgo / 60000)
  if (m < 2) return 'just now'
  if (m < 60) return `${m}m ago`
  return `${Math.round(m / 60)}h ago`
}

const PORTAL_STATE = {
  agent: {
    state: 'working',
    // Case-driven synopsis (RUN-4c #40): describes the investigation, not the
    // blocked queue (that lives in the BlockedActionsPane). Long enough to
    // exercise the hero's Show-more truncation.
    headline:
      'Reconstructed a hands-on-keyboard intrusion across NORTHWIND: RDP lateral movement from WS-FINANCE-03 into the DC-01 domain controller, a "UpdateSync" persistence task side-loading an unsigned DLL, and bulk staging of HR-confidential records on FS-01. 47 findings proposed from 3 fused evidence sources; the highest-severity chain is corroborated by firewall flow logs.',
    metrics: { records_parsed: 1284402, findings_proposed: 47, sources_fused: 3 },
  },
  // Blocked tool-calls — the agent ran these autonomously; policy guards
  // stopped them. Surfaced READ-ONLY in the BlockedActionsPane.
  blocked_actions: [
    {
      id: 'ba-1',
      title: 'Unseal EV-014 for memory re-hash',
      tool: 'mcp:evidence.unseal',
      guard: 'Integrity guard',
      target: 'EV-014 · WS-FINANCE-03-mem.img',
      timestamp: _fmtTs(4 * 60000),
      detail: 'The policy sandbox blocks direct evidence unsealing — integrity guard prevents modification of sealed artifacts.',
    },
    {
      id: 'ba-2',
      title: 'Acquire volatile memory from WS-FINANCE-03',
      tool: 'mcp:acquire.memory',
      guard: 'Acquisition guard',
      target: 'WS-FINANCE-03',
      timestamp: _fmtTs(9 * 60000),
      detail: 'Live acquisition requires an active, non-archived case. Acquisition guard enforces this constraint.',
    },
    {
      id: 'ba-3',
      title: 'Quarantine payload.dll → isolated vault',
      tool: 'mcp:fs.quarantine',
      guard: 'Egress guard',
      target: 'C:\\ProgramData\\sync.dll',
      timestamp: _fmtTs(14 * 60000),
      detail: 'File egress outside the evidence directory is blocked by the egress guard policy.',
    },
    {
      id: 'ba-4',
      title: 'Read raw network capture — FW-EDGE',
      tool: 'mcp:pcap.read',
      guard: 'Read-only guard',
      target: 'FW-EDGE-capture.pcap',
      timestamp: _fmtTs(22 * 60000),
      detail: 'Raw PCAP access requires explicit evidence registration; read-only guard blocked unregistered path.',
    },
  ],
  // Keep gated_actions for backward compat with sidebar badge + deriveAgentState queued count
  gated_actions: [],
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
  // Evidence registry for the Evidence tab pilot (P1). Read via
  // portalState.evidence_items in EvidenceTab; this avoids a new top-level
  // store key (the store surface is frozen). MOCK DATA — synthetic, not real.
  evidence_items: null, // populated below after EVIDENCE_ITEMS is defined
}

const ACTIVE_CASE = {
  case_id: 'CASE-2026-0410',
  name: 'NORTHWIND',
  title: 'NORTHWIND intrusion investigation',
  status: 'active',
  examiner: 'e.varga',
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
  { id: 'rpt-7f3a21', profile: 'executive', examiner: 'e.varga', created_at: iso(12 * H) },
  { id: 'rpt-9c0b54', profile: 'technical', examiner: 'e.varga', created_at: iso(30 * H) },
]

const IOCS = [
  { id: 'ioc-1', type: 'ip', value: '185.99.12.44' },
  { id: 'ioc-2', type: 'account', value: 'svc-backup' },
]

const USER = { examiner: 'E. Varga', role: 'examiner' }

// Multi-case switcher demo: active / inactive / sealed lifecycle badges.
const CASES = [
  { id: 'CASE-2026-0410', name: 'NORTHWIND', status: 'active', active: true },
  { id: 'CASE-2026-0388', name: 'REDWING', status: 'inactive', active: false },
  { id: 'CASE-2026-0351', name: 'BLACKSMITH', status: 'sealed', active: false },
]

// ─────────────────────────────────────────────────────────────────────────
// Evidence registry — representative DFIR artifacts for the Evidence tab pilot.
// MOCK DATA ONLY — no real case data; sha256 hashes are fabricated.
// Hosts: WS-FINANCE-03, DC-01, FS-01, WS-07. Types: disk/memory/network.
// Custody: mix of Sealed/Unsealed/Pending to exercise all badge states.
// ─────────────────────────────────────────────────────────────────────────
export const EVIDENCE_ITEMS = [
  {
    id: 'EV-001',
    name: 'WS-FINANCE-03-disk.E01',
    description: 'Physical disk image — WS-FINANCE-03 (finance workstation)',
    type: 'disk',
    host: 'WS-FINANCE-03',
    size_bytes: 512_000_000_000,
    size_label: '512 GB',
    acquired_at: iso(3 * D + 1 * H),
    acquired_by: 'e.varga',
    acquisition_method: 'FTK Imager 4.7 — physical sector-level',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'a4f9c1e2b3d07f8e6a5b2c1d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2',
    hmac_ok: true,
    custody_events: [
      { at: iso(3 * D), by: 'e.varga', action: 'acquired', note: 'Forensic image acquired on-site.' },
      { at: iso(2.8 * D), by: 'e.varga', action: 'sealed', note: 'Manifest v3 sealed; immutability applied.' },
    ],
    finding_refs: ['F-001', 'F-004'],
  },
  {
    id: 'EV-002',
    name: 'WS-FINANCE-03-mem.img',
    description: 'Live memory dump — WS-FINANCE-03 (16 GB RAM)',
    type: 'memory',
    host: 'WS-FINANCE-03',
    size_bytes: 17_179_869_184,
    size_label: '16 GB',
    acquired_at: iso(3 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'WinPmem 4.0 — raw physical memory',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'b5a0d2f3c4e18f9a7b6c3d2e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4',
    hmac_ok: true,
    custody_events: [
      { at: iso(3 * D), by: 'e.varga', action: 'acquired', note: 'RAM captured before shutdown.' },
      { at: iso(2.9 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: [],
  },
  {
    id: 'EV-003',
    name: 'DC-01-disk.E01',
    description: 'Physical disk image — DC-01 (primary domain controller)',
    type: 'disk',
    host: 'DC-01',
    size_bytes: 1_099_511_627_776,
    size_label: '1 TB',
    acquired_at: iso(2.5 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'FTK Imager 4.7 — physical sector-level',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'c6b1e3f4d5a29a0b8c7d4e3f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5',
    hmac_ok: true,
    custody_events: [
      { at: iso(2.5 * D), by: 'e.varga', action: 'acquired', note: 'Acquired from live running system (shadow copy).' },
      { at: iso(2.4 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-001', 'F-002', 'F-005'],
  },
  {
    id: 'EV-004',
    name: 'DC-01-mem.img',
    description: 'Live memory dump — DC-01 (64 GB RAM)',
    type: 'memory',
    host: 'DC-01',
    size_bytes: 68_719_476_736,
    size_label: '64 GB',
    acquired_at: iso(2.4 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'WinPmem 4.0 — raw physical memory',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'd7c2f4a5e6b3ab1c9d8e5f4a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6',
    hmac_ok: true,
    custody_events: [
      { at: iso(2.4 * D), by: 'e.varga', action: 'acquired', note: 'Memory acquired before reboot.' },
      { at: iso(2.3 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-002'],
  },
  {
    id: 'EV-005',
    name: 'FS-01-disk.E01',
    description: 'Physical disk image — FS-01 (file server, HR share)',
    type: 'disk',
    host: 'FS-01',
    size_bytes: 2_199_023_255_552,
    size_label: '2 TB',
    acquired_at: iso(2 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'FTK Imager 4.7 — physical sector-level',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'e8d3a5b6f7c4bc2dae9f6a5b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7',
    hmac_ok: true,
    custody_events: [
      { at: iso(2 * D), by: 'e.varga', action: 'acquired', note: 'Acquired HR share host disk.' },
      { at: iso(1.9 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-003'],
  },
  {
    id: 'EV-006',
    name: 'FW-EDGE-capture.pcap',
    description: 'Firewall perimeter PCAP — 72-hour window (incident window)',
    type: 'network',
    host: 'FW-EDGE',
    size_bytes: 42_949_672_960,
    size_label: '40 GB',
    acquired_at: iso(1.8 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'tshark ring-buffer export from FW-EDGE logging host',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'f9e4b6c7a8d5cd3ebfa0a7b6c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8',
    hmac_ok: true,
    custody_events: [
      { at: iso(1.8 * D), by: 'e.varga', action: 'acquired', note: 'Exported from FW syslog retention.' },
      { at: iso(1.7 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-004'],
  },
  {
    id: 'EV-007',
    name: 'WS-07-disk.E01',
    description: 'Physical disk image — WS-07 (potential staging host)',
    type: 'disk',
    host: 'WS-07',
    size_bytes: 256_000_000_000,
    size_label: '256 GB',
    acquired_at: iso(1.5 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'FTK Imager 4.7 — physical sector-level',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'a0f5c7d8b9e6de4fca1b8c7d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9',
    hmac_ok: true,
    custody_events: [
      { at: iso(1.5 * D), by: 'e.varga', action: 'acquired', note: 'Acquired; awaiting seal.' },
      { at: iso(1.4 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: [],
  },
  {
    id: 'EV-008',
    name: 'DC-01-evtx-bundle.zip',
    description: 'Windows event log bundle — DC-01 (Security/System/Application EVTX)',
    type: 'logs',
    host: 'DC-01',
    size_bytes: 4_831_838_208,
    size_label: '4.5 GB',
    acquired_at: iso(2.6 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'EvtxECmd batch export; zipped for transport',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'b1a6d8e9c0f7ef5a0b2c9d8e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0',
    hmac_ok: true,
    custody_events: [
      { at: iso(2.6 * D), by: 'e.varga', action: 'acquired', note: 'EVTX logs exported and zipped.' },
      { at: iso(2.5 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-001', 'F-005'],
  },
  {
    id: 'EV-009',
    name: 'FS-01-vss-shadow.E01',
    description: 'VSS shadow copy — FS-01 (48h before incident)',
    type: 'disk',
    host: 'FS-01',
    size_bytes: 549_755_813_888,
    size_label: '512 GB',
    acquired_at: iso(1.2 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'FTK Imager — Volume Shadow Copy extraction',
    custody_status: 'unsealed',
    write_protected: false,
    manifest_entry: 'v2',
    sha256: 'c2b7e9f0d1a8f06b1c3d0e9f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1',
    hmac_ok: false,
    custody_events: [
      { at: iso(1.2 * D), by: 'e.varga', action: 'acquired', note: 'VSS shadow extracted for baseline comparison.' },
      { at: iso(1.1 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v2.' },
      { at: iso(0.5 * D), by: 'e.varga', action: 'unsealed', note: 'Unsealed for re-acquisition from newer shadow copy.' },
    ],
    finding_refs: ['F-003'],
  },
  {
    id: 'EV-010',
    name: 'WS-FINANCE-03-zeek.tar.gz',
    description: 'Zeek flow logs — WS-FINANCE-03 endpoint tap (72h window)',
    type: 'network',
    host: 'WS-FINANCE-03',
    size_bytes: 1_073_741_824,
    size_label: '1 GB',
    acquired_at: iso(2 * D + 3 * H),
    acquired_by: 'e.varga',
    acquisition_method: 'Zeek offline analysis of mirrored traffic; tar bundle',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'd3c8f0a1e2b9a17c2d4e1f0a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    hmac_ok: true,
    custody_events: [
      { at: iso(2 * D + 3 * H), by: 'e.varga', action: 'acquired', note: 'Zeek bundle from network capture station.' },
      { at: iso(2 * D + 2 * H), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-004'],
  },
  {
    id: 'EV-011',
    name: 'DC-01-ntds.dit',
    description: 'AD database — DC-01 NTDS.dit (VSS extraction, offline)',
    type: 'registry',
    host: 'DC-01',
    size_bytes: 734_003_200,
    size_label: '700 MB',
    acquired_at: iso(2.5 * D + 2 * H),
    acquired_by: 'e.varga',
    acquisition_method: 'Volume Shadow Copy extraction via secretsdump approach',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'e4d9a1b2f3c0b28d3e5f2a1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
    hmac_ok: true,
    custody_events: [
      { at: iso(2.5 * D + 2 * H), by: 'e.varga', action: 'acquired', note: 'NTDS.dit extracted from VSS snapshot.' },
      { at: iso(2.4 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-001'],
  },
  {
    id: 'EV-012',
    name: 'WS-07-mem.img',
    description: 'Live memory dump — WS-07 (8 GB RAM, staging host)',
    type: 'memory',
    host: 'WS-07',
    size_bytes: 8_589_934_592,
    size_label: '8 GB',
    acquired_at: iso(1.4 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'WinPmem 4.0 — raw physical memory',
    custody_status: 'pending',
    write_protected: false,
    manifest_entry: null,
    sha256: 'f5e0b2c3a4d1c39e4f6a3b2c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
    hmac_ok: null,
    custody_events: [
      { at: iso(1.4 * D), by: 'e.varga', action: 'acquired', note: 'Acquired WS-07 RAM.' },
    ],
    finding_refs: [],
  },
  {
    id: 'EV-013',
    name: 'WS-FINANCE-03-registry.reg',
    description: 'Registry hive export — WS-FINANCE-03 (SYSTEM + SOFTWARE hives)',
    type: 'registry',
    host: 'WS-FINANCE-03',
    size_bytes: 419_430_400,
    size_label: '400 MB',
    acquired_at: iso(2.8 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'RECmd offline hive export via VSS snapshot',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'a1c2e3f4b5d6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    hmac_ok: true,
    custody_events: [
      { at: iso(2.8 * D), by: 'e.varga', action: 'acquired', note: 'Registry hives exported from VSS snapshot.' },
      { at: iso(2.7 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-002'],
  },
  {
    id: 'EV-014',
    name: 'DC-01-network-capture.pcap',
    description: 'Internal network capture — DC-01 interface (24h incident window)',
    type: 'network',
    host: 'DC-01',
    size_bytes: 5_368_709_120,
    size_label: '5 GB',
    acquired_at: iso(2.3 * D),
    acquired_by: 'e.varga',
    acquisition_method: 'tshark on span port — DC-01 internal NIC mirror',
    custody_status: 'sealed',
    write_protected: true,
    manifest_entry: 'v3',
    sha256: 'b2d3f4a5c6e7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
    hmac_ok: true,
    custody_events: [
      { at: iso(2.3 * D), by: 'e.varga', action: 'acquired', note: 'DC-01 NIC capture exported from span port logger.' },
      { at: iso(2.2 * D), by: 'e.varga', action: 'sealed', note: 'Sealed in manifest v3.' },
    ],
    finding_refs: ['F-001', 'F-004'],
  },
]

// Wire evidence_items into PORTAL_STATE so EvidenceTab can read it from the
// portalState store key without needing a new top-level store key.
PORTAL_STATE.evidence_items = EVIDENCE_ITEMS

/** Selector: returns EVIDENCE_ITEMS. The custody_status on each item is
 *  already the source of truth. 14 total / 12 sealed (EV-001..006, EV-007,
 *  EV-008, EV-010..011, EV-013, EV-014) / 1 unsealed (EV-009) / 1 pending (EV-012).
 *  Agrees with PORTAL_STATE.evidence = { sealed: 12, total: 14 }.
 */
export function selectEvidenceRegistry() {
  return EVIDENCE_ITEMS
}

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
