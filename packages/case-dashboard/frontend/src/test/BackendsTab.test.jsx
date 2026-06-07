import { describe, it, expect, vi, beforeEach } from 'vitest'
import { getBackends, postValidateBackend, postRegisterBackend, postReloadBackends } from '../api/endpoints'

// Mock endpoints to avoid actual API calls during logic testing
vi.mock('../api/endpoints', () => ({
  getBackends: vi.fn(),
  deleteBackend: vi.fn(),
  postRegisterBackend: vi.fn(),
  postValidateBackend: vi.fn(),
  postReloadBackends: vi.fn(),
  postStartService: vi.fn(),
  postStopService: vi.fn(),
  postRestartService: vi.fn(),
  getCommitChallenge: vi.fn(),
}))

describe('Backends tab payload and logic validation', () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it('correctly parses args textarea (newline vs JSON array)', () => {
    const parseArgs = (argsStr) => {
      let parsedArgs = []
      const trimmed = argsStr.trim()
      if (trimmed) {
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
          try {
            parsedArgs = JSON.parse(trimmed)
            if (!Array.isArray(parsedArgs)) {
              throw new Error()
            }
          } catch (e) {
            parsedArgs = trimmed.split('\n').map(a => a.trim()).filter(Boolean)
          }
        } else {
          parsedArgs = trimmed.split('\n').map(a => a.trim()).filter(Boolean)
        }
      }
      return parsedArgs
    }

    // Newline-separated list
    expect(parseArgs('a\nb\n   c   ')).toEqual(['a', 'b', 'c'])
    // JSON Array
    expect(parseArgs('["a", "b", "c"]')).toEqual(['a', 'b', 'c'])
    // Broken JSON fall back to newline split
    expect(parseArgs('["a", "b"')).toEqual(['["a", "b"'])
  })

  it('correctly compiles environment variable grid list to record object', () => {
    const compileEnv = (envList) => {
      const envObj = {}
      envList.forEach(({ key, value }) => {
        if (key.trim()) {
          envObj[key.trim()] = value
        }
      })
      return envObj
    }

    const envList = [
      { key: 'PORT', value: '8080' },
      { key: '  HOST ', value: '127.0.0.1' },
      { key: '', value: 'ignored' },
    ]
    expect(compileEnv(envList)).toEqual({
      PORT: '8080',
      HOST: '127.0.0.1',
    })
  })

  it('evaluates service row button enablement states correctly', () => {
    const getButtonStates = (backend) => {
      const hasUnmet = backend.unmet_requires && backend.unmet_requires.length > 0
      return {
        canStart: backend.enabled && !backend.started && !hasUnmet,
        canStop: backend.started,
        canRestart: backend.enabled && backend.started && !hasUnmet,
      }
    }

    // Gated active backend (unmet requirements)
    const gated = { enabled: true, started: false, unmet_requires: ['unmet:req'], requires: ['unmet:req'] }
    expect(getButtonStates(gated)).toEqual({
      canStart: false,
      canStop: false,
      canRestart: false,
    })

    // Stopped, enabled backend with requirements met
    const stoppedMet = { enabled: true, started: false, unmet_requires: [], requires: ['met:req'] }
    expect(getButtonStates(stoppedMet)).toEqual({
      canStart: true,
      canStop: false,
      canRestart: false,
    })

    // Active, started backend that becomes gated (started stays true, stop must be enabled)
    const activeGated = { enabled: true, started: true, unmet_requires: ['new-unmet:req'], requires: [] }
    expect(getButtonStates(activeGated)).toEqual({
      canStart: false,
      canStop: true,
      canRestart: false,
    })

    // Disabled, started backend (should allow stop)
    const disabledStarted = { enabled: false, started: true, unmet_requires: [], requires: [] }
    expect(getButtonStates(disabledStarted)).toEqual({
      canStart: false,
      canStop: true,
      canRestart: false,
    })
  })
})
