import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import * as endpoints from '@/api/endpoints'
import { sortTodos, parseRelated } from '@/components/todos/todos-utils'
import { TodosTab } from '@/components/todos/TodosTab'

// ─────────────────────────────────────────────────────────────────────────
// TodosTab.test.jsx — pure logic (sortTodos filter+sort · parseRelated) PLUS
// interaction coverage of the CRUD flows (toggle status · delete with confirm)
// and the RBAC gate (analyst role hides write actions). Endpoints are mocked;
// the store is seeded so the tab renders populated.
// ─────────────────────────────────────────────────────────────────────────

const TODOS = [
  { todo_id: 'T-001', description: 'High open task', priority: 'high', status: 'open', examiner: 'e.varga', related_findings: ['F-001'], created_at: '2026-06-20T01:00:00Z' },
  { todo_id: 'T-002', description: 'Low completed task', priority: 'low', status: 'completed', examiner: 'm.reyes', related_findings: [], created_at: '2026-06-20T02:00:00Z' },
  { todo_id: 'T-003', description: 'Medium open task', priority: 'medium', status: 'open', examiner: 'e.varga', related_findings: [], created_at: '2026-06-20T00:00:00Z' },
]

describe('todos-utils — pure logic', () => {
  it('sortTodos: priority desc then created_at asc; filters by priority + status', () => {
    const sorted = sortTodos(TODOS, 'all', 'all')
    expect(sorted.map((t) => t.todo_id)).toEqual(['T-001', 'T-003', 'T-002'])

    expect(sortTodos(TODOS, 'all', 'open').map((t) => t.todo_id)).toEqual(['T-001', 'T-003'])
    expect(sortTodos(TODOS, 'low', 'all').map((t) => t.todo_id)).toEqual(['T-002'])
  })

  it('parseRelated: splits, trims, drops blanks', () => {
    expect(parseRelated('F-001, F-002 ,  , F-003')).toEqual(['F-001', 'F-002', 'F-003'])
    expect(parseRelated('')).toEqual([])
  })
})

vi.mock('@/api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    createTodo: vi.fn(),
    updateTodo: vi.fn(),
    deleteTodo: vi.fn(),
  }
})

beforeEach(() => {
  vi.clearAllMocks()
  useStore.setState({
    toasts: [],
    todos: TODOS,
    summary: { todos: { open: 2, completed: 1 } },
    user: { examiner: 'test', role: 'examiner' },
    isLoading: false,
    activeTab: 'todos',
  })
})

describe('TodosTab — interaction', () => {
  it('renders the populated table with sorted rows', () => {
    render(<TodosTab />)
    expect(screen.getByText('T-001')).toBeInTheDocument()
    expect(screen.getByText('High open task')).toBeInTheDocument()
    expect(screen.getByText(/2 open/)).toBeInTheDocument()
  })

  it('toggle status calls updateTodo with the next status', async () => {
    endpoints.updateTodo.mockResolvedValue({ ...TODOS[0], status: 'completed' })
    render(<TodosTab />)
    fireEvent.click(screen.getAllByRole('button', { name: /^complete$/i })[0])
    await waitFor(() => expect(endpoints.updateTodo).toHaveBeenCalledWith('T-001', { status: 'completed' }))
  })

  it('delete confirms then calls deleteTodo', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    endpoints.deleteTodo.mockResolvedValue({})
    render(<TodosTab />)
    fireEvent.click(screen.getAllByRole('button', { name: /^delete$/i })[0])
    await waitFor(() => expect(endpoints.deleteTodo).toHaveBeenCalledWith('T-001'))
    window.confirm.mockRestore()
  })

  it('related-finding link navigates to the Findings tab', () => {
    render(<TodosTab />)
    fireEvent.click(screen.getByRole('button', { name: 'F-001' }))
    expect(useStore.getState().activeTab).toBe('findings')
    expect(useStore.getState().selectedFindingId).toBe('F-001')
  })

  it('RBAC: analyst role hides write actions', () => {
    useStore.setState({ user: { examiner: 'a', role: 'analyst' } })
    render(<TodosTab />)
    expect(screen.queryByRole('button', { name: /new todo/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /^delete$/i })).toBeNull()
  })
})
