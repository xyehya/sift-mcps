import { describe, expect, it } from 'vitest'

import { confidenceGrade, confidenceScore } from '../components/findings/findings-utils'

describe('confidenceScore', () => {
  it('prefers an explicit numeric confidence_score (clamped 0–100)', () => {
    expect(confidenceScore({ confidence_score: 91 })).toBe(91)
    expect(confidenceScore({ confidence_score: 140 })).toBe(100)
    expect(confidenceScore({ confidence_score: -5 })).toBe(0)
  })

  it('maps the categorical confidence when no score is present', () => {
    expect(confidenceScore({ confidence: 'HIGH' })).toBe(92)
    expect(confidenceScore({ confidence: 'MEDIUM' })).toBe(74)
    expect(confidenceScore({ confidence: 'LOW' })).toBe(48)
    expect(confidenceScore({ confidence: 'SPECULATIVE' })).toBe(30)
  })

  it('returns null when confidence is unknown', () => {
    expect(confidenceScore({})).toBeNull()
  })
})

describe('confidenceGrade', () => {
  it('grades ≥85 jade · ≥65 amber · else crimson (graded, not branded)', () => {
    expect(confidenceGrade(92).text).toBe('text-status-approved')
    expect(confidenceGrade(85).text).toBe('text-status-approved')
    expect(confidenceGrade(74).text).toBe('text-sev-med')
    expect(confidenceGrade(65).text).toBe('text-sev-med')
    expect(confidenceGrade(48).text).toBe('text-sev-high')
    expect(confidenceGrade(0).text).toBe('text-sev-high')
  })

  it('exposes a token CSS var for the SVG stroke (no raw hex)', () => {
    expect(confidenceGrade(92).stroke).toBe('var(--status-approved)')
    expect(confidenceGrade(70).stroke).toBe('var(--sev-med)')
    expect(confidenceGrade(10).stroke).toBe('var(--sev-high)')
  })

  it('returns null for an unknown score', () => {
    expect(confidenceGrade(null)).toBeNull()
  })
})
