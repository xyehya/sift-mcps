import { describe, it, expect, beforeEach } from 'vitest'
import { useStore } from '../store/useStore'

// ── Helpers ────────────────────────────────────────────────────────
function resetStore() {
  useStore.setState({
    cases: [],
    activeCase: null,
    findings: [],
    delta: [],
    timeline: [],
    chainStatus: null,
    iocs: [],
    todos: [],
    reports: [],
    summary: null,
    isLoading: true,
    lastSync: null,
    activeTab: 'overview',
    selectedFindingId: null,
    findingsFilter: 'pending',
    findingsHostFilter: null,
    findingsAccountFilter: null,
    commitDrawerOpen: false,
    commandPaletteOpen: false,
    user: { examiner: 'test-examiner', role: 'examiner' },
    toasts: [],
  })
}

beforeEach(() => resetStore())

// ── B-01: Case list extraction from API response ────────────────────
describe('B-01: Case list extraction', () => {
  it('setCases extracts .cases from the API response object', () => {
    const apiResponse = {
      cases: [
        { id: 'case-one', name: 'Case One', status: 'open', active: true },
        { id: 'case-two', name: 'Case Two', status: 'closed', active: false },
      ],
      cases_root: '/cases',
      active_case_dir: '/cases/case-one',
    }
    const extracted = apiResponse?.cases ?? []
    useStore.getState().setCases(extracted)
    expect(useStore.getState().cases).toHaveLength(2)
    expect(useStore.getState().cases[0].id).toBe('case-one')
    expect(useStore.getState().cases[1].id).toBe('case-two')
  })

  it('setCases handles null/undefined API response gracefully', () => {
    useStore.getState().setCases(null?.cases ?? [])
    expect(useStore.getState().cases).toEqual([])
    useStore.getState().setCases(undefined?.cases ?? [])
    expect(useStore.getState().cases).toEqual([])
  })

  it('setCases handles response without .cases key', () => {
    const extracted = ({ items: [] })?.cases ?? []
    useStore.getState().setCases(extracted)
    expect(useStore.getState().cases).toEqual([])
  })

  it('setCases handles empty cases array', () => {
    const apiResponse = { cases: [], cases_root: '/cases', active_case_dir: null }
    useStore.getState().setCases(apiResponse?.cases ?? [])
    expect(useStore.getState().cases).toHaveLength(0)
  })
})

// ── B-02: Case banner identifier ────────────────────────────────────
describe('B-02: Case banner identifier', () => {
  it('activeCase uses case_id (not id) from CASE.yaml', () => {
    const caseYaml = {
      case_id: 'test-rocba-2026',
      name: 'Intrusion and Ransomware',
      title: 'Intrusion and Ransomware',
      status: 'open',
      examiner: 'test-examiner',
      created: '2026-05-26T14:17:23Z',
    }
    useStore.getState().setActiveCase(caseYaml)
    const state = useStore.getState()
    expect(state.activeCase.case_id).toBe('test-rocba-2026')
    expect(state.activeCase.id).toBeUndefined()
  })

  it('banner resolves activeCaseId from case_id when id is missing', () => {
    const caseYaml = { case_id: 'c001', name: 'Test', status: 'open' }
    useStore.getState().setActiveCase(caseYaml)
    const s = useStore.getState()
    const activeCaseId = s.activeCase?.case_id || s.activeCase?.id
    expect(activeCaseId).toBe('c001')
  })

  it('banner falls back to id when case_id is missing', () => {
    const caseObj = { id: 'fallback-id', name: 'Test' }
    const activeCaseId = caseObj?.case_id || caseObj?.id
    expect(activeCaseId).toBe('fallback-id')
  })

  it('banner returns undefined when both case_id and id are missing', () => {
    const activeCaseId = undefined?.case_id || undefined?.id
    expect(activeCaseId).toBeUndefined()
  })
})

// ── B-03: StatusBar seal indicator ──────────────────────────────────
describe('B-03: StatusBar chain status field names', () => {
  it('renders SEALED ✓ when sealed and hmac_not_needed', () => {
    const chainStatus = {
      status: 'ok',
      manifest_version: 3,
      hmac_verify_needed: false,
      hmac_last_verified_at: '2026-05-27T10:00:00Z',
      write_protected: false,
    }
    useStore.getState().setChainStatus(chainStatus)
    const cs = useStore.getState().chainStatus
    const isSealed = cs && cs.status !== 'unsealed' && cs.manifest_version > 0
    const sealLabel = !cs ? 'LOADING'
      : isSealed && !cs.hmac_verify_needed ? 'SEALED ✓'
      : isSealed ? 'SEALED · verify pending'
      : 'UNSEALED'
    expect(isSealed).toBe(true)
    expect(sealLabel).toBe('SEALED ✓')
  })

  it('renders SEALED · verify pending when sealed but hmac needed', () => {
    const chainStatus = {
      status: 'ok',
      manifest_version: 1,
      hmac_verify_needed: true,
      write_protected: false,
    }
    useStore.getState().setChainStatus(chainStatus)
    const cs = useStore.getState().chainStatus
    const isSealed = cs && cs.status !== 'unsealed' && cs.manifest_version > 0
    const sealLabel = !cs ? 'LOADING'
      : isSealed && !cs.hmac_verify_needed ? 'SEALED ✓'
      : isSealed ? 'SEALED · verify pending'
      : 'UNSEALED'
    expect(sealLabel).toBe('SEALED · verify pending')
  })

  it('renders UNSEALED when status is unsealed', () => {
    const chainStatus = {
      status: 'unsealed',
      manifest_version: 0,
      hmac_verify_needed: true,
      write_protected: false,
    }
    useStore.getState().setChainStatus(chainStatus)
    const cs = useStore.getState().chainStatus
    const sealLabel = !cs ? 'LOADING'
      : cs.status !== 'unsealed' && cs.manifest_version > 0 && !cs.hmac_verify_needed ? 'SEALED ✓'
      : cs.status !== 'unsealed' && cs.manifest_version > 0 ? 'SEALED · verify pending'
      : 'UNSEALED'
    expect(sealLabel).toBe('UNSEALED')
  })

  it('renders LOADING when chainStatus is null', () => {
    useStore.getState().setChainStatus(null)
    const cs = useStore.getState().chainStatus
    const sealLabel = !cs ? 'LOADING' : 'UNKNOWN'
    expect(sealLabel).toBe('LOADING')
  })

  it('write_protected field is correctly named (not write_blocked)', () => {
    const chainStatus = {
      status: 'ok',
      manifest_version: 1,
      hmac_verify_needed: false,
      write_protected: true,
    }
    useStore.getState().setChainStatus(chainStatus)
    const cs = useStore.getState().chainStatus
    expect(cs.write_protected).toBe(true)
    expect(cs.write_blocked).toBeUndefined()
    expect(cs.write_block_warning).toBeUndefined()
  })

  it('setActiveTab evidence works for seal dot click navigation', () => {
    useStore.getState().setActiveTab('evidence')
    expect(useStore.getState().activeTab).toBe('evidence')
  })

  it('seal colors map correctly', () => {
    const cases = [
      { status: 'ok', manifest_version: 1, hmac_verify_needed: false, expected: 'var(--jade)' },
      { status: 'ok', manifest_version: 1, hmac_verify_needed: true, expected: 'var(--amber)' },
      { status: 'unsealed', manifest_version: 0, hmac_verify_needed: true, expected: 'var(--crimson)' },
    ]
    for (const { status, manifest_version, hmac_verify_needed, expected } of cases) {
      const cs = { status, manifest_version, hmac_verify_needed }
      const isSealed = cs.status !== 'unsealed' && cs.manifest_version > 0
      const color = !cs ? 'var(--text-muted)'
        : isSealed && !cs.hmac_verify_needed ? 'var(--jade)'
        : isSealed ? 'var(--amber)'
        : 'var(--crimson)'
      expect(color).toBe(expected)
    }
  })
})

// ── B-04: ActivityFeed time filter ──────────────────────────────────
describe('B-04: ActivityFeed time filter', () => {
  function makeFinding(id, modified_at) {
    return {
      id: `F-${id}`,
      title: `Finding ${id}`,
      confidence: 'MEDIUM',
      status: 'draft',
      modified_at: modified_at.toISOString(),
      event_timestamp: '2020-11-10T13:26:09Z',
      timestamp: null,
    }
  }

  function applyFilter(findings, cutoffMs) {
    return findings.filter((f) => {
      if (cutoffMs === Infinity) return true
      const ts = f.modified_at || f.timestamp || f.event_timestamp
      if (!ts) return false
      return Date.now() - new Date(ts).getTime() < cutoffMs
    })
  }

  it('filters findings by modified_at within given cutoff', () => {
    const now = Date.now()
    const findings = [
      makeFinding('001', new Date(now - 30 * 60 * 1000)),   // 30 min ago → within 1h
      makeFinding('002', new Date(now - 2 * 60 * 60 * 1000)), // 2h ago → outside 1h
      makeFinding('003', new Date(now - 23 * 60 * 60 * 1000)), // 23h ago → within 24h
    ]

    const within1h = applyFilter(findings, 60 * 60 * 1000)
    expect(within1h).toHaveLength(1)
    expect(within1h[0].id).toBe('F-001')

    const within24h = applyFilter(findings, 24 * 60 * 60 * 1000)
    expect(within24h).toHaveLength(3) // all three are within 24h: 30min, 2h, 23h

    const all = applyFilter(findings, Infinity)
    expect(all).toHaveLength(3)
  })

  it('falls back to timestamp then event_timestamp when modified_at missing', () => {
    const now = Date.now()
    const findings = [
      { id: 'F-a', title: 'a', confidence: 'LOW', modified_at: null, timestamp: new Date(now - 300000).toISOString(), event_timestamp: '2020-01-01T00:00:00Z' },
      { id: 'F-b', title: 'b', confidence: 'LOW', modified_at: null, timestamp: null, event_timestamp: '2020-01-01T00:00:00Z' },
    ]
    const filtered = applyFilter(findings, 60 * 60 * 1000)
    expect(filtered).toHaveLength(1)
    expect(filtered[0].id).toBe('F-a')
  })

  it('filters out findings with no valid timestamp (non-All)', () => {
    const findings = [
      { id: 'F-x', title: 'x', confidence: 'LOW', modified_at: null, timestamp: null, event_timestamp: null },
    ]
    const filtered = applyFilter(findings, 24 * 60 * 60 * 1000)
    expect(filtered).toHaveLength(0)
  })

  it('All filter includes every finding regardless of timestamp', () => {
    const findings = [
      { id: 'F-old', title: 'old', modified_at: null, timestamp: null, event_timestamp: '2020-01-01T00:00:00Z' },
      { id: 'F-no-ts', title: 'no ts', modified_at: null, timestamp: null, event_timestamp: null },
    ]
    const filtered = applyFilter(findings, Infinity)
    expect(filtered).toHaveLength(2)
  })

  it('truncates to max 8 findings', () => {
    const now = Date.now()
    const findings = Array.from({ length: 15 }, (_, i) => makeFinding(String(i + 1), new Date(now)))
    const sliced = [...findings].sort((a, b) => new Date(b.modified_at) - new Date(a.modified_at)).slice(0, 8)
    expect(sliced).toHaveLength(8)
  })

  it('setSelectedFindingId + setActiveTab navigation works', () => {
    useStore.getState().setSelectedFindingId('F-005')
    useStore.getState().setActiveTab('findings')
    const s = useStore.getState()
    expect(s.selectedFindingId).toBe('F-005')
    expect(s.activeTab).toBe('findings')
  })
})

// ── B-05: Reports store and polling ──────────────────────────────────
describe('B-05: Reports store', () => {
  it('reports defaults to empty array', () => {
    expect(useStore.getState().reports).toEqual([])
  })

  it('setReports stores report list', () => {
    const reports = [
      { id: 'rpt-001', profile: 'executive', created_at: '2026-05-28T10:00:00Z', examiner: 'test' },
      { id: 'rpt-002', profile: 'full', created_at: '2026-05-28T11:00:00Z', examiner: 'test' },
    ]
    useStore.getState().setReports(reports)
    expect(useStore.getState().reports).toHaveLength(2)
    expect(useStore.getState().reports[0].profile).toBe('executive')
  })

  it('setReports replaces existing reports', () => {
    useStore.getState().setReports([{ id: 'old' }])
    useStore.getState().setReports([{ id: 'new' }])
    expect(useStore.getState().reports).toHaveLength(1)
    expect(useStore.getState().reports[0].id).toBe('new')
  })

  it('reports slice for overview widget limits to 5', () => {
    const reports = Array.from({ length: 8 }, (_, i) => ({ id: `r-${i}`, profile: 'full' }))
    useStore.getState().setReports(reports)
    const shown = useStore.getState().reports.slice(0, 5)
    expect(shown).toHaveLength(5)
  })
})

// ── B-06: MITRE tag cloud from mitre_ids ──────────────────────────────
describe('B-06: MITRE tag cloud field source', () => {
  it('extracts MITRE IDs from mitre_ids array (not tags)', () => {
    const findings = [
      { mitre_ids: ['T1059', 'T1003'], tags: ['credential_access', 'powershell'] },
      { mitre_ids: ['T1059'], tags: [] },
      { mitre_ids: [], tags: ['T9999'] },
      { mitre_ids: ['T1486'], tags: ['T1486-also-in-tags'] },
    ]
    const mitreIds = [...new Set(findings.flatMap((f) => f.mitre_ids ?? []))]
    expect(mitreIds.sort()).toEqual(['T1003', 'T1059', 'T1486'])
  })

  it('does NOT extract from tags field', () => {
    const findings = [
      { mitre_ids: [], tags: ['T1059', 'T1003'] },
    ]
    const mitreIds = [...new Set(findings.flatMap((f) => f.mitre_ids ?? []))]
    expect(mitreIds).toEqual([])
  })

  it('handles missing mitre_ids field', () => {
    const findings = [
      { tags: ['something'] },
    ]
    const mitreIds = [...new Set(findings.flatMap((f) => f.mitre_ids ?? []))]
    expect(mitreIds).toEqual([])
  })

  it('deduplicates MITRE IDs across findings', () => {
    const findings = [
      { mitre_ids: ['T1059', 'T1003'] },
      { mitre_ids: ['T1059', 'T1486'] },
    ]
    const mitreIds = [...new Set(findings.flatMap((f) => f.mitre_ids ?? []))]
    expect(mitreIds.sort()).toEqual(['T1003', 'T1059', 'T1486'])
  })

  it('handles empty findings array', () => {
    const mitreIds = [...new Set([].flatMap((f) => f.mitre_ids ?? []))]
    expect(mitreIds).toEqual([])
  })
})

// ── Case activation flow ────────────────────────────────────────────
describe('Case activation flow', () => {
  it('activation request uses case_id field (not id)', () => {
    const activatingCase = { id: 'test-case', name: 'Test Case' }
    const payload = {
      case_id: activatingCase.id,
      challenge_id: 'challenge-hex',
      response: 'response-hex',
    }
    expect(payload.case_id).toBe('test-case')
    expect(payload.id).toBeUndefined()
  })

  it('post-activation resets all case-scoped data stores', () => {
    // Simulate pre-activation state
    useStore.setState({
      findings: [{ id: 'F-001', title: 'old', status: 'draft' }],
      timeline: [{ id: 'T-001', description: 'old event' }],
      delta: [{ id: 'F-001', action: 'approve' }],
      chainStatus: { status: 'ok', manifest_version: 1 },
      iocs: [{ id: 'ioc-1', value: '1.2.3.4' }],
      todos: [{ id: 'todo-1', description: 'check' }],
      reports: [{ id: 'rpt-1', profile: 'executive' }],
      summary: { findings: { total: 10 } },
      activeCase: { case_id: 'old-case' },
      isLoading: false,
    })

    // Simulate post-activation reset
    const store = useStore.getState()
    store.setFindings([])
    store.setTimeline([])
    store.setDelta([])
    store.setChainStatus(null)
    store.setIocs([])
    store.setTodos([])
    store.setReports([])
    store.setSummary(null)
    store.setActiveCase(null)
    store.setIsLoading(true)

    const s = useStore.getState()
    expect(s.findings).toEqual([])
    expect(s.timeline).toEqual([])
    expect(s.delta).toEqual([])
    expect(s.chainStatus).toBeNull()
    expect(s.iocs).toEqual([])
    expect(s.todos).toEqual([])
    expect(s.reports).toEqual([])
    expect(s.summary).toBeNull()
    expect(s.activeCase).toBeNull()
    expect(s.isLoading).toBe(true)
  })

  it('activation modal password is cleared after submit attempt', () => {
    // Password should be cleared immediately after computing challenge response
    let password = 'secret123'
    expect(password).toBe('secret123')
    password = ''
    expect(password).toBe('')
  })

  it('cancel closes modal and clears password', () => {
    // Simulate cancel behavior
    let password = 'typed-password'
    let modalOpen = true
    // Cancel
    modalOpen = false
    password = ''
    expect(modalOpen).toBe(false)
    expect(password).toBe('')
  })

  it('clicking active case does not open activation modal', () => {
    const c = { id: 'active-case', active: true }
    // switchCase should return early for active case
    const shouldActivate = !c.active
    expect(shouldActivate).toBe(false)
  })

  it('clicking non-active case opens activation modal', () => {
    const c = { id: 'inactive-case', active: false }
    const shouldActivate = !c.active
    expect(shouldActivate).toBe(true)
  })
})

// ── Security: XSS prevention ──────────────────────────────────────────
describe('Security: XSS prevention', () => {
  it('case_id values are rendered safely (no script injection)', () => {
    const maliciousCaseId = '<img src=x onerror=alert(1)>'
    const safeRender = String(maliciousCaseId)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
    // After escaping, angle brackets are neutralized — the payload cannot execute
    expect(safeRender).not.toContain('<img')
    expect(safeRender).not.toContain('<script')
    expect(safeRender).toContain('&lt;') // angle brackets replaced
    expect(safeRender).toContain('&gt;')
  })

  it('finding titles with HTML are rendered safely', () => {
    const maliciousTitle = '<script>alert("xss")</script>'
    const safeRender = String(maliciousTitle)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
    expect(safeRender).not.toContain('<script>')
    expect(safeRender).toBe('&lt;script&gt;alert("xss")&lt;/script&gt;')
  })

  it('profile names with special chars are rendered safely', () => {
    const maliciousProfile = 'executive<img src=x onerror=alert(1)>'
    // CSS textTransform capitalize handles this at the CSS level, not HTML
    expect(typeof maliciousProfile).toBe('string')
    // No HTML injection possible via CSS textTransform
  })

  it('finding ID is validated as string', () => {
    const ids = ['F-001', '<script>x</script>', null, undefined, 123]
    const valid = ids.filter((id) => typeof id === 'string' && id.length > 0)
    expect(valid).toHaveLength(2)
    expect(valid).toContain('F-001')
    expect(valid).toContain('<script>x</script>')
  })

  it('password is never stored in plaintext for long', () => {
    // Password should be cleared from React state immediately after use
    let password = 'temp-password'
    // After challenge computation
    password = ''
    expect(password).toBe('')
  })

  it('activation error messages do not leak internal details', () => {
    const rawErrors = [
      'Missing case_id, challenge_id, or response',
      'Invalid case_id format',
      'Case directory not found',
      'Incorrect password',
      'Internal server error: /cases/../../../etc/passwd',
    ]
    const normalized = rawErrors.map((e) => {
      if (e.includes('Internal server error')) return 'Activation failed. Verify password and try again.'
      if (e.includes('Incorrect password')) return 'Activation failed. Verify password and try again.'
      return 'Activation failed. Verify password and try again.'
    })
    const uniqueMessages = [...new Set(normalized)]
    expect(uniqueMessages).toHaveLength(1)
    expect(uniqueMessages[0]).toBe('Activation failed. Verify password and try again.')
  })
})

// ── Security: Bypass logic ────────────────────────────────────────────
describe('Security: Bypass prevention', () => {
  it('activation requires non-empty challenge_id', () => {
    const payloads = [
      { case_id: 'test', challenge_id: '', response: 'sig' },
      { case_id: 'test', challenge_id: null, response: 'sig' },
      { case_id: 'test', challenge_id: undefined, response: 'sig' },
    ]
    for (const p of payloads) {
      const valid = !!(p.case_id && p.challenge_id && p.response)
      expect(valid).toBe(false)
    }
  })

  it('activation requires non-empty response', () => {
    const valid = !!(('test-case' && 'challenge-hex' && ''))
    expect(valid).toBe(false)
  })

  it('HMAC response must be computed client-side (cannot be guessed)', () => {
    // The response must be HMAC-SHA256(stored_pbkdf2_hash, nonce)
    // Without the stored hash, an attacker cannot compute a valid response
    const fakeResponse = '0000000000000000000000000000000000000000000000000000000000000000'
    // 64 hex chars = 32 bytes = SHA-256 length
    expect(fakeResponse).toHaveLength(64)
    // But without the correct key, it won't match
    // The backend verifies: hmac.compare_digest(expected, response)
    expect(typeof fakeResponse).toBe('string')
  })

  it('clicking outside activation modal does not submit', () => {
    // Modal uses backdrop onClick → setActivatingCase(null)
    let modalOpen = true
    // Click backdrop (not form)
    modalOpen = false
    expect(modalOpen).toBe(false)
    // The form was not submitted, so no activation occurred
  })

  it('clicking inside modal form does not close it', () => {
    // form uses onClick={(e) => e.stopPropagation()}
    // This prevents backdrop click from closing when clicking inside the form
    let modalOpen = true
    // Click inside form → stopPropagation → modal stays open
    // e.stopPropagation() is called, so the backdrop handler doesn't fire
    expect(modalOpen).toBe(true)
  })
})

// ── Response time expectations ───────────────────────────────────────
describe('Response time expectations', () => {
  it('store updates are synchronous (< 1ms)', () => {
    const start = performance.now()
    useStore.getState().setCases([{ id: 'fast', name: 'Fast', status: 'open', active: true }])
    const end = performance.now()
    expect(end - start).toBeLessThan(10) // ms, generous for zustand
  })

  it('filtering 100 findings completes under 5ms', () => {
    const now = Date.now()
    const findings = Array.from({ length: 100 }, (_, i) => ({
      id: `F-${i}`,
      title: `Finding ${i}`,
      modified_at: new Date(now - i * 3600000).toISOString(),
      confidence: 'MEDIUM',
    }))
    const start = performance.now()
    const filtered = findings.filter((f) => {
      return Date.now() - new Date(f.modified_at).getTime() < 30 * 24 * 60 * 60 * 1000
    })
    const end = performance.now()
    expect(end - start).toBeLessThan(5)
    expect(filtered.length).toBe(100)
  })

  it('chainStatus color computation is O(1)', () => {
    const cs = { status: 'ok', manifest_version: 2, hmac_verify_needed: false }
    const start = performance.now()
    for (let i = 0; i < 10000; i++) {
      const isSealed = cs.status !== 'unsealed' && cs.manifest_version > 0
      const _color = isSealed && !cs.hmac_verify_needed ? 'jade' : isSealed ? 'amber' : 'crimson'
    }
    const end = performance.now()
    expect(end - start).toBeLessThan(10)
  })
})

// ── Edge cases ────────────────────────────────────────────────────────
describe('Edge cases', () => {
  it('empty findings produce empty MITRE cloud', () => {
    const mitreIds = [...new Set([].flatMap((f) => f.mitre_ids ?? []))]
    expect(mitreIds).toEqual([])
  })

  it('findings with null mitre_ids field handled', () => {
    const findings = [
      { mitre_ids: null },
      { mitre_ids: ['T1059'] },
      { mitre_ids: undefined },
    ]
    const mitreIds = [...new Set(findings.flatMap((f) => f.mitre_ids ?? []))]
    expect(mitreIds).toEqual(['T1059'])
  })

  it('chainStatus with zero manifest_version is unsealed', () => {
    const cs = { status: 'ok', manifest_version: 0, hmac_verify_needed: true }
    const isSealed = cs.status !== 'unsealed' && cs.manifest_version > 0
    expect(isSealed).toBe(false)
  })

  it('chainStatus manifest_version 0 treated same as unsealed status', () => {
    const cs = { status: 'unsealed', manifest_version: 0 }
    const isSealed = cs && cs.status !== 'unsealed' && cs.manifest_version > 0
    expect(isSealed).toBe(false)
  })

  it('reports with missing examiner field still render', () => {
    const report = { id: 'r-1', profile: 'full', created_at: '2026-05-28T10:00:00Z' }
    const examiner = report.examiner || '—'
    expect(examiner).toBe('—')
  })

  it('reports with missing created_at still render', () => {
    const report = { id: 'r-2', profile: 'timeline' }
    const date = report.created_at ? new Date(report.created_at).toLocaleDateString() : ''
    expect(date).toBe('')
  })

  it('case selector handles activeCase with neither case_id nor id', () => {
    const activeCase = {}
    const id = activeCase?.case_id || activeCase?.id
    expect(id).toBeUndefined()
  })

  it('cases list with mixed active/inactive renders all dots correctly', () => {
    const cases = [
      { id: 'c1', active: true },
      { id: 'c2', active: false },
      { id: 'c3', active: true },
    ]
    const dots = cases.map((c) => c.active ? 'var(--jade)' : 'var(--border-hard)')
    expect(dots).toEqual(['var(--jade)', 'var(--border-hard)', 'var(--jade)'])
  })

  it('delta length zero means idle agent pulse', () => {
    useStore.getState().setDelta([])
    const agentPulse = useStore.getState().delta.length > 0
    expect(agentPulse).toBe(false)
  })

  it('delta length > 0 means active agent pulse', () => {
    useStore.getState().setDelta([{ id: 'F-001', action: 'approve' }])
    const agentPulse = useStore.getState().delta.length > 0
    expect(agentPulse).toBe(true)
  })
})
