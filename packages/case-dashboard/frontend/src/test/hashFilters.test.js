import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

import { parseHashTab, parseHashFilters, navigateToFindings } from '../hooks/useHashRoute'

// The confidence/severity filter rides the hash query (`#/findings?sev=high`).
// These pin the deep-link plumbing: the tab still routes (query tolerated), the
// filter parses back out, and navigateToFindings writes a shareable URL.

beforeEach(() => {
  window.location.hash = ''
})
afterEach(() => {
  window.location.hash = ''
})

describe('parseHashTab tolerates the filter query (backward compatible)', () => {
  it('still routes the tab when a ?sev= query is attached', () => {
    expect(parseHashTab('#/findings?sev=high')).toBe('findings')
    expect(parseHashTab('#/findings')).toBe('findings')
    expect(parseHashTab('#/nope?sev=high')).toBeNull()
  })
})

describe('parseHashFilters', () => {
  it('extracts a valid severity (UPPERCASE), ignores junk', () => {
    expect(parseHashFilters('#/findings?sev=high')).toEqual({ sev: 'HIGH' })
    expect(parseHashFilters('#/findings?sev=SPECULATIVE')).toEqual({ sev: 'SPECULATIVE' })
    expect(parseHashFilters('#/findings')).toEqual({})
    expect(parseHashFilters('#/findings?sev=banana')).toEqual({})
    expect(parseHashFilters('')).toEqual({})
  })
})

describe('navigateToFindings', () => {
  it('writes a shareable hash carrying the severity + selects the tab', () => {
    const setActiveTab = vi.fn()
    navigateToFindings(setActiveTab, { sev: 'high' })
    expect(window.location.hash).toBe('#/findings?sev=high')
    expect(setActiveTab).toHaveBeenCalledWith('findings')
    expect(parseHashFilters(window.location.hash)).toEqual({ sev: 'HIGH' })
  })

  it('writes a clean hash with no/invalid severity', () => {
    const setActiveTab = vi.fn()
    navigateToFindings(setActiveTab, {})
    expect(window.location.hash).toBe('#/findings')
    navigateToFindings(setActiveTab, { sev: 'banana' })
    expect(window.location.hash).toBe('#/findings')
  })
})
