import { useState } from 'react'

import { createTodo, updateTodo, deleteTodo } from '@/api/endpoints'
import { parseRelated } from './todos-utils'

// ─────────────────────────────────────────────────────────────────────────
// useTodos — owns the TODO mutation flows (create · toggle-status · inline edit
// · delete) plus the create-form + inline-edit drafts and the per-row in-flight
// guard. Reads `todos` from the store and writes back via setTodos, keeping the
// list in sync with the optimistic API result. Keeps TodosTab a thin
// orchestrator. Mock/real split is at the API adapter layer (no isMock here).
// ─────────────────────────────────────────────────────────────────────────

const EMPTY_CREATE = { description: '', priority: 'medium', assignee: '', related: '' }

export function useTodos({ todos, setTodos, addToast }) {
  // Create form
  const [creating, setCreating] = useState(false)
  const [draft, setDraft] = useState(EMPTY_CREATE)
  const [savingNew, setSavingNew] = useState(false)

  // Inline edit
  const [editingId, setEditingId] = useState(null)
  const [editDraft, setEditDraft] = useState({ description: '', priority: 'medium' })

  // Per-row in-flight guard (toggle / delete / save)
  const [busyId, setBusyId] = useState(null)

  async function handleCreate() {
    const description = draft.description.trim()
    if (!description) {
      addToast('Description is required', 'error')
      return
    }
    setSavingNew(true)
    try {
      const created = await createTodo({
        description,
        priority: draft.priority,
        assignee: draft.assignee.trim(),
        related_findings: parseRelated(draft.related),
      })
      if (created) {
        setTodos([...todos, created])
        addToast(`Created ${created.todo_id}`, 'success')
        setDraft(EMPTY_CREATE)
        setCreating(false)
      }
    } catch (ex) {
      addToast(ex.message, 'error')
    } finally {
      setSavingNew(false)
    }
  }

  async function handleToggleStatus(todo) {
    const next = (todo.status ?? 'open') === 'completed' ? 'open' : 'completed'
    setBusyId(todo.todo_id)
    try {
      const updated = await updateTodo(todo.todo_id, { status: next })
      if (updated) {
        setTodos(todos.map((t) => (t.todo_id === todo.todo_id ? updated : t)))
        addToast(`${todo.todo_id} marked ${next}`, next === 'completed' ? 'success' : 'info')
      }
    } catch (ex) {
      addToast(ex.message, 'error')
    } finally {
      setBusyId(null)
    }
  }

  function startEdit(todo) {
    setEditingId(todo.todo_id)
    setEditDraft({ description: todo.description ?? '', priority: todo.priority ?? 'medium' })
  }

  function cancelEdit() {
    setEditingId(null)
  }

  async function handleSaveEdit(todo) {
    const description = editDraft.description.trim()
    if (!description) {
      addToast('Description cannot be empty', 'error')
      return
    }
    setBusyId(todo.todo_id)
    try {
      const updated = await updateTodo(todo.todo_id, { description, priority: editDraft.priority })
      if (updated) {
        setTodos(todos.map((t) => (t.todo_id === todo.todo_id ? updated : t)))
        addToast(`Updated ${todo.todo_id}`, 'success')
        setEditingId(null)
      }
    } catch (ex) {
      addToast(ex.message, 'error')
    } finally {
      setBusyId(null)
    }
  }

  async function handleDelete(todo) {
    if (!window.confirm(`Delete ${todo.todo_id}? This cannot be undone.`)) return
    setBusyId(todo.todo_id)
    try {
      await deleteTodo(todo.todo_id)
      setTodos(todos.filter((t) => t.todo_id !== todo.todo_id))
      addToast(`Deleted ${todo.todo_id}`, 'info')
    } catch (ex) {
      addToast(ex.message, 'error')
    } finally {
      setBusyId(null)
    }
  }

  return {
    creating,
    setCreating,
    draft,
    setDraft,
    savingNew,
    editingId,
    editDraft,
    setEditDraft,
    busyId,
    handleCreate,
    handleToggleStatus,
    startEdit,
    cancelEdit,
    handleSaveEdit,
    handleDelete,
  }
}
