import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { AgentActivityFeed } from '../components/overview/AgentActivityFeed'
import { useStore } from '../store/useStore'

beforeEach(() => {
  window.matchMedia =
    window.matchMedia ||
    ((query) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
      dispatchEvent: () => false,
    }))
  useStore.setState({ agentActivity: [] })
})

describe('AgentActivityFeed', () => {
  it('renders DB-backed agent activity from the store', () => {
    useStore.setState({
      agentActivity: [
        {
          id: 'evt-activity',
          ts: '2026-06-08T00:01:00+00:00',
          kind: 'discovery',
          text: 'Recorded finding - External RDP (HIGH)',
        },
      ],
    })

    render(<AgentActivityFeed />)

    expect(screen.getByText('Agent activity')).toBeInTheDocument()
    expect(screen.getByText('Recorded finding - External RDP (HIGH)')).toBeInTheDocument()
    expect(screen.queryByText(/MFT parsing/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/185\.66\.0\.12/)).not.toBeInTheDocument()
  })

  it('shows an empty state when no audit-backed events exist', () => {
    render(<AgentActivityFeed />)

    expect(screen.getByText('No agent activity recorded yet.')).toBeInTheDocument()
  })
})
