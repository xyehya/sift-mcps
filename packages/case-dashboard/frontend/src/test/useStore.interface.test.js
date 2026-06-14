import { describe, expect, it } from 'vitest'
import { useStore, useStoreSlice } from '../store/useStore'

const STATE_KEYS = [
  'activeCase',
  'activeTab',
  'cases',
  'chainStatus',
  'commandPaletteOpen',
  'commitDrawerOpen',
  'delta',
  'findings',
  'findingsAccountFilter',
  'findingsFilter',
  'findingsHostFilter',
  'iocs',
  'isLoading',
  'lastSync',
  'portalState',
  'reports',
  'selectedFindingId',
  'summary',
  'timeline',
  'toasts',
  'todos',
  'user',
]

const ACTION_KEYS = [
  'addToast',
  'dismissToast',
  'setActiveCase',
  'setActiveTab',
  'setCases',
  'setChainStatus',
  'setCommandPaletteOpen',
  'setCommitDrawerOpen',
  'setDelta',
  'setFindings',
  'setFindingsAccountFilter',
  'setFindingsFilter',
  'setFindingsHostFilter',
  'setIocs',
  'setIsLoading',
  'setLastSync',
  'setPortalState',
  'setReports',
  'setSelectedFindingId',
  'setSummary',
  'setTimeline',
  'setTodos',
  'setUser',
]

describe('useStore interface', () => {
  it('keeps the dashboard store state/action contract stable', () => {
    const state = useStore.getState()

    expect(Object.keys(state).sort()).toEqual([...STATE_KEYS, ...ACTION_KEYS].sort())
  })

  it('keeps action entries callable', () => {
    const state = useStore.getState()

    for (const key of ACTION_KEYS) {
      expect(typeof state[key], key).toBe('function')
    }
  })

  it('exports the shallow selector helper for component slices', () => {
    expect(typeof useStoreSlice).toBe('function')
  })
})
