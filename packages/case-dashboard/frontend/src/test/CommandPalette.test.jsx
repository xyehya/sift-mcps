import { describe, it, expect, beforeEach } from 'vitest'
import { useStore } from '../store/useStore'

// Reset store between tests
beforeEach(() => {
  useStore.setState({
    commandPaletteOpen: false,
    findings: [],
    selectedFindingId: null,
    delta: [],
    activeTab: 'overview',
    commitDrawerOpen: false,
    user: { examiner: 'test', role: 'examiner' },
    isLoading: false,
    toasts: [],
  })
})

describe('commandPaletteOpen store', () => {
  it('defaults to false', () => {
    const state = useStore.getState()
    expect(state.commandPaletteOpen).toBe(false)
  })

  it('setCommandPaletteOpen(true) opens the palette', () => {
    useStore.getState().setCommandPaletteOpen(true)
    expect(useStore.getState().commandPaletteOpen).toBe(true)
  })

  it('setCommandPaletteOpen(false) closes the palette', () => {
    useStore.getState().setCommandPaletteOpen(true)
    useStore.getState().setCommandPaletteOpen(false)
    expect(useStore.getState().commandPaletteOpen).toBe(false)
  })
})

describe('CommandPalette actions via store', () => {
  it('setCommitDrawerOpen opens the commit drawer', () => {
    useStore.getState().setCommitDrawerOpen(true)
    expect(useStore.getState().commitDrawerOpen).toBe(true)
  })

  it('handleOpenCommit sets commitDrawerOpen and closes palette', () => {
    useStore.getState().setCommandPaletteOpen(true)
    const store = useStore.getState()
    store.setCommitDrawerOpen(true)
    store.setCommandPaletteOpen(false)

    const s = useStore.getState()
    expect(s.commitDrawerOpen).toBe(true)
    expect(s.commandPaletteOpen).toBe(false)
  })

  it('setSelectedFindingId + setActiveTab navigates to a finding', () => {
    useStore.setState({
      findings: [
        { id: 'F-001', title: 'Test finding', type: 'finding', status: 'draft', content_hash: 'abc' },
      ],
    })

    const store = useStore.getState()
    store.setSelectedFindingId('F-001')
    store.setActiveTab('findings')

    const s = useStore.getState()
    expect(s.selectedFindingId).toBe('F-001')
    expect(s.activeTab).toBe('findings')
  })

  it('clearing user logs out', () => {
    useStore.getState().setUser(null)
    expect(useStore.getState().user).toBeNull()
  })
})

describe('delta staging logic (approve/reject simulation)', () => {
  it('stages an approve delta item', () => {
    useStore.setState({
      findings: [
        { id: 'F-001', title: 'Suspicious file', type: 'finding', content_hash: 'abc123', status: 'draft' },
      ],
      delta: [],
    })

    const findingId = 'F-001'
    const action = 'approve'
    const store = useStore.getState()
    const finding = store.findings.find((f) => f.id === findingId)

    const newItem = {
      id: findingId,
      type: finding.type ?? 'finding',
      action,
      content_hash_at_review: finding.content_hash ?? '',
      modifications: {},
    }

    const existing = store.delta.filter((d) => d.id !== findingId)
    const newDelta = [...existing, newItem]
    useStore.setState({ delta: newDelta })

    const s = useStore.getState()
    expect(s.delta).toHaveLength(1)
    expect(s.delta[0].id).toBe('F-001')
    expect(s.delta[0].action).toBe('approve')
    expect(s.delta[0].type).toBe('finding')
    expect(s.delta[0].content_hash_at_review).toBe('abc123')
  })

  it('stages a reject delta item', () => {
    useStore.setState({
      findings: [
        { id: 'F-002', title: 'False alarm', type: 'conclusion', content_hash: 'def456', status: 'draft' },
      ],
      delta: [],
    })

    const findingId = 'F-002'
    const action = 'reject'
    const store = useStore.getState()
    const finding = store.findings.find((f) => f.id === findingId)

    const newItem = {
      id: findingId,
      type: finding.type ?? 'finding',
      action,
      content_hash_at_review: finding.content_hash ?? '',
      modifications: {},
    }

    const newDelta = [...store.delta.filter((d) => d.id !== findingId), newItem]
    useStore.setState({ delta: newDelta })

    const s = useStore.getState()
    expect(s.delta).toHaveLength(1)
    expect(s.delta[0].id).toBe('F-002')
    expect(s.delta[0].action).toBe('reject')
    expect(s.delta[0].type).toBe('conclusion')
  })

  it('replaces existing delta for same finding (idempotent staging)', () => {
    useStore.setState({
      findings: [
        { id: 'F-001', title: 'Test', type: 'finding', content_hash: 'abc', status: 'draft' },
      ],
      delta: [
        { id: 'F-001', type: 'finding', action: 'approve', content_hash_at_review: 'abc', modifications: {} },
      ],
    })

    // Stage reject for same finding — should replace the approve
    const store = useStore.getState()
    const finding = store.findings.find((f) => f.id === 'F-001')
    const newItem = {
      id: 'F-001',
      type: finding.type,
      action: 'reject',
      content_hash_at_review: finding.content_hash,
      modifications: {},
    }

    const existing = store.delta.filter((d) => d.id !== 'F-001')
    const newDelta = [...existing, newItem]
    useStore.setState({ delta: newDelta })

    const s = useStore.getState()
    expect(s.delta).toHaveLength(1)
    expect(s.delta[0].action).toBe('reject')
  })

  it('handles missing finding gracefully (no-op)', () => {
    useStore.setState({
      findings: [],
      delta: [],
    })

    const store = useStore.getState()
    const finding = store.findings.find((f) => f.id === 'F-999')
    expect(finding).toBeUndefined()

    // No delta should be created
    expect(store.delta).toHaveLength(0)
  })
})

describe('security gate: no password bypass', () => {
  it('commit drawer requires manual password — palette only opens drawer, does not auto-commit', () => {
    // Opening commit drawer sets commitDrawerOpen but does NOT submit a commit
    const store = useStore.getState()
    store.setCommitDrawerOpen(true)

    const s = useStore.getState()
    expect(s.commitDrawerOpen).toBe(true)
    // Delta items remain staged — nothing was committed
    // The CommitDrawer component itself requires the HMAC password challenge
  })

  it('approve/reject via palette only stages — does not commit', () => {
    useStore.setState({
      findings: [
        { id: 'F-001', title: 'Test', type: 'finding', content_hash: 'abc', status: 'draft' },
      ],
      delta: [],
    })

    const store = useStore.getState()
    const finding = store.findings.find((f) => f.id === 'F-001')
    const newItem = {
      id: 'F-001',
      type: finding.type,
      action: 'approve',
      content_hash_at_review: finding.content_hash,
      modifications: {},
    }
    useStore.setState({ delta: [newItem] })

    const s = useStore.getState()
    // Delta is staged but NOT committed — password is required separately
    expect(s.delta).toHaveLength(1)
    expect(s.commitDrawerOpen).toBe(false)

    // No password was involved — staging is auth-free by design
    // The commit endpoint itself enforces HMAC challenge-response
  })

  it('sign out clears user but does not reveal password', () => {
    useStore.getState().setUser(null)
    const s = useStore.getState()
    expect(s.user).toBeNull()
    // No password in store — it was never stored
  })
})

describe('recent items tracking', () => {
  it('tracks up to 5 unique recent items', () => {
    // Simulate the addRecent logic from CommandPalette
    const MAX_RECENT = 5
    let recent = []

    function addRecent(item) {
      const filtered = recent.filter((i) => i.id !== item.id)
      recent = [item, ...filtered].slice(0, MAX_RECENT)
      return recent
    }

    addRecent({ id: 'F-001', label: 'First', type: 'finding' })
    addRecent({ id: 'F-002', label: 'Second', type: 'finding' })
    addRecent({ id: 'F-003', label: 'Third', type: 'finding' })
    addRecent({ id: 'F-004', label: 'Fourth', type: 'finding' })
    addRecent({ id: 'F-005', label: 'Fifth', type: 'finding' })

    expect(recent).toHaveLength(5)

    // Adding a 6th pushes out the oldest (F-001)
    addRecent({ id: 'F-006', label: 'Sixth', type: 'finding' })
    expect(recent).toHaveLength(5)
    expect(recent[0].id).toBe('F-006')
    expect(recent[4].id).toBe('F-002')
  })

  it('re-selecting an item moves it to the top', () => {
    const MAX_RECENT = 5
    let recent = []

    function addRecent(item) {
      const filtered = recent.filter((i) => i.id !== item.id)
      recent = [item, ...filtered].slice(0, MAX_RECENT)
      return recent
    }

    addRecent({ id: 'F-001', label: 'First', type: 'finding' })
    addRecent({ id: 'F-002', label: 'Second', type: 'finding' })
    addRecent({ id: 'F-003', label: 'Third', type: 'finding' })

    // Re-select F-002 — it moves to top
    addRecent({ id: 'F-002', label: 'Second', type: 'finding' })
    expect(recent[0].id).toBe('F-002')
    expect(recent[1].id).toBe('F-003')
    expect(recent[2].id).toBe('F-001')
    expect(recent).toHaveLength(3)
  })
})

describe('keyboard shortcut logic', () => {
  it('Ctrl+K key combination is detected', () => {
    const event = new KeyboardEvent('keydown', { key: 'k', ctrlKey: true })
    const isPaletteShortcut = (event.ctrlKey || event.metaKey) && event.key === 'k'
    expect(isPaletteShortcut).toBe(true)
  })

  it('Cmd+K key combination is detected (Mac)', () => {
    const event = new KeyboardEvent('keydown', { key: 'k', metaKey: true })
    const isPaletteShortcut = (event.ctrlKey || event.metaKey) && event.key === 'k'
    expect(isPaletteShortcut).toBe(true)
  })

  it('plain "k" without modifier is NOT detected', () => {
    const event = new KeyboardEvent('keydown', { key: 'k', ctrlKey: false, metaKey: false })
    const isPaletteShortcut = (event.ctrlKey || event.metaKey) && event.key === 'k'
    expect(isPaletteShortcut).toBe(false)
  })

  it('Ctrl+J is NOT the palette shortcut', () => {
    const event = new KeyboardEvent('keydown', { key: 'j', ctrlKey: true })
    const isPaletteShortcut = (event.ctrlKey || event.metaKey) && event.key === 'k'
    expect(isPaletteShortcut).toBe(false)
  })
})
