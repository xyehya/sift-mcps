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
  it('renders the populated table with sorted rows; no static "(N of N)" chrome', () => {
    render(<TodosTab />)
    expect(screen.getByText('T-001')).toBeInTheDocument()
    expect(screen.getByText('High open task')).toBeInTheDocument()
    // Static "(3 of 3)" / "X open · Y completed" decoration was removed (§B3).
    expect(screen.queryByText(/of 3/)).toBeNull()
    expect(screen.queryByText(/\d+ open$/)).toBeNull()
    // Unfiltered view shows no count chrome.
    expect(screen.queryByText(/shown/)).toBeNull()
  })

  it('shows a live "N shown" count only while filtering', () => {
    render(<TodosTab />)
    fireEvent.change(screen.getByLabelText(/filter by status/i), { target: { value: 'open' } })
    expect(screen.getByText(/2 shown/)).toBeInTheDocument()
  })

  it('primary action toggles status — calls updateTodo with the next status', async () => {
    endpoints.updateTodo.mockResolvedValue({ ...TODOS[0], status: 'completed' })
    render(<TodosTab />)
    // The primary row affordance is an icon button labelled "Complete".
    fireEvent.click(screen.getAllByRole('button', { name: /^complete$/i })[0])
    await waitFor(() => expect(endpoints.updateTodo).toHaveBeenCalledWith('T-001', { status: 'completed' }))
  })

  // Radix DropdownMenuTrigger opens on pointerdown (left button) — open the
  // first row's "⋯" overflow menu and return the located trigger.
  function openFirstOverflow() {
    const trigger = screen.getAllByRole('button', { name: /more actions/i })[0]
    fireEvent.pointerDown(trigger, { button: 0, ctrlKey: false })
    fireEvent.pointerUp(trigger, { button: 0 })
  }

  it('delete lives in the ⋯ overflow menu, confirms, then calls deleteTodo', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    endpoints.deleteTodo.mockResolvedValue({})
    render(<TodosTab />)
    openFirstOverflow()
    fireEvent.click(await screen.findByRole('menuitem', { name: /delete/i }))
    await waitFor(() => expect(endpoints.deleteTodo).toHaveBeenCalledWith('T-001'))
    window.confirm.mockRestore()
  })

  it('edit lives in the ⋯ overflow menu and opens the inline editor', async () => {
    render(<TodosTab />)
    openFirstOverflow()
    fireEvent.click(await screen.findByRole('menuitem', { name: /edit/i }))
    expect(await screen.findByLabelText(/edit description/i)).toBeInTheDocument()
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
    // No primary toggle, no overflow menu (which holds edit/delete) for analysts.
    expect(screen.queryByRole('button', { name: /^complete$/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /more actions/i })).toBeNull()
  })
})
