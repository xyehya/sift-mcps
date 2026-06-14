import { useMemo, useState } from 'react'
import { Command } from 'cmdk'
import { useStoreSlice } from '../../store/useStore'
import { postDelta, postLogout } from '../../api/endpoints'

const MAX_RECENT = 5

export function CommandPalette() {
  const {
    commandPaletteOpen, setCommandPaletteOpen,
    findings, selectedFindingId,
    setSelectedFindingId, setActiveTab,
    delta, setDelta,
    setCommitDrawerOpen, setUser, addToast,
  } = useStoreSlice((state) => ({
    commandPaletteOpen: state.commandPaletteOpen,
    setCommandPaletteOpen: state.setCommandPaletteOpen,
    findings: state.findings,
    selectedFindingId: state.selectedFindingId,
    setSelectedFindingId: state.setSelectedFindingId,
    setActiveTab: state.setActiveTab,
    delta: state.delta,
    setDelta: state.setDelta,
    setCommitDrawerOpen: state.setCommitDrawerOpen,
    setUser: state.setUser,
    addToast: state.addToast,
  }))

  const [recentItems, setRecentItems] = useState([])
  const findingById = useMemo(() => new Map(findings.map((finding) => [finding.id, finding])), [findings])

  // Close on Escape — cmdk handles this natively, but we also track via store
  function close() {
    setCommandPaletteOpen(false)
  }

  function addRecent(item) {
    setRecentItems((prev) => {
      const filtered = prev.filter((i) => i.id !== item.id)
      return [item, ...filtered].slice(0, MAX_RECENT)
    })
  }

  // --- Finding navigation ---
  function handleFindingSelect(id) {
    const f = findingById.get(id)
    if (!f) return
    addRecent({ id: f.id, label: `${f.id}  ${(f.title ?? '').slice(0, 56)}`, type: 'finding' })
    setSelectedFindingId(id)
    setActiveTab('findings')
    close()
  }

  // --- Stage approve / reject (same logic as FindingsTab.stageAction) ---
  async function stageAction(findingId, action) {
    const finding = findingById.get(findingId)
    if (!finding) return
    const newItem = {
      id: findingId,
      type: finding.type ?? 'finding',
      action,
      content_hash_at_review: finding.content_hash ?? '',
      modifications: {},
    }
    const existing = delta.filter((d) => d.id !== findingId)
    const newDelta = [...existing, newItem]
    try {
      await postDelta({ items: newDelta })
      setDelta(newDelta)
      addToast(
        `${action === 'approve' ? 'Approved' : 'Rejected'} ${findingId} — staged`,
        action === 'approve' ? 'success' : 'warn'
      )
    } catch (ex) {
      addToast(ex.message, 'error')
    }
  }

  function handleApproveCurrent() {
    const fid = selectedFindingId
    if (!fid) {
      addToast('No finding selected — open Findings first', 'info')
      close()
      return
    }
    stageAction(fid, 'approve')
    close()
  }

  function handleRejectCurrent() {
    const fid = selectedFindingId
    if (!fid) {
      addToast('No finding selected — open Findings first', 'info')
      close()
      return
    }
    stageAction(fid, 'reject')
    close()
  }

  function handleOpenCommit() {
    setCommitDrawerOpen(true)
    close()
  }

  function handleRefresh() {
    window.location.reload()
  }

  async function handleSignOut() {
    try {
      await postLogout()
    } catch {
      // ignore network errors — clear state anyway
    }
    setUser(null)
    window.location.reload()
  }

  // Build the full item list
  const findingItems = useMemo(() => findings.map((f) => ({
    id: f.id,
    label: `${f.id}  ${(f.title ?? '').slice(0, 56)}`,
    type: 'finding',
    keywords: [f.id, f.title ?? ''],
  })), [findings])

  // Recent items rendered first
  const recentIds = useMemo(() => new Set(recentItems.map((r) => r.id)), [recentItems])
  const recentFindingItems = useMemo(() => (
    recentItems.filter((r) => r.type === 'finding' && findingById.has(r.id))
  ), [findingById, recentItems])

  return (
    <Command.Dialog
      open={commandPaletteOpen}
      onOpenChange={(open) => {
        if (!open) close()
      }}
      label="Command Palette"
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      style={{ background: 'rgba(0,0,0,0.55)' }}
    >
      <div
        className="w-full max-w-lg rounded-lg border shadow-2xl overflow-hidden"
        style={{
          background: 'var(--bg-surface)',
          borderColor: 'var(--border-soft)',
        }}
      >
        {/* Search input */}
        <div className="flex items-center border-b px-3" style={{ borderColor: 'var(--border-faint)' }}>
          <svg
            className="w-4 h-4 mr-2 shrink-0"
            viewBox="0 0 20 20"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            style={{ color: 'var(--text-muted)' }}
          >
            <circle cx="9" cy="9" r="6" />
            <line x1="14.5" y1="14.5" x2="18" y2="18" />
          </svg>
          <Command.Input
            placeholder="Search findings or run a command..."
            autoFocus
            className="flex-1 h-11 bg-transparent border-none outline-none font-sans text-sm placeholder:text-text-ghost"
            style={{ color: 'var(--text-primary)' }}
          />
          <kbd
            className="ml-2 px-1.5 py-0.5 rounded font-mono text-[10px]"
            style={{ color: 'var(--text-muted)', background: 'var(--bg-raised)', border: '1px solid var(--border-faint)' }}
          >
            esc
          </kbd>
        </div>

        <Command.List
          className="max-h-72 overflow-y-auto p-1"
          style={{ scrollbarWidth: 'thin', scrollbarColor: 'var(--border-soft) transparent' }}
        >
          <Command.Empty className="py-8 text-center font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
            No results found.
          </Command.Empty>

          {/* Recently selected */}
          {recentFindingItems.length > 0 && (
            <Command.Group
              heading="Recently selected"
              className="px-2 pt-2 pb-1"
              style={{ '--cmdk-group-heading-color': 'var(--text-muted)' }}
            >
              {recentFindingItems.map((item) => (
                <Command.Item
                  key={`recent-${item.id}`}
                  value={`recent-${item.id}`}
                  onSelect={() => handleFindingSelect(item.id)}
                  className="flex items-center gap-2 px-2 py-1.5 rounded text-xs cursor-pointer data-[selected=true]:bg-cyan-dim data-[selected=true]:text-cyan"
                  style={{
                    color: 'var(--text-primary)',
                  }}
                >
                  <span className="w-3 h-3 shrink-0 opacity-40">
                    <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <circle cx="6" cy="6" r="4" />
                      <line x1="6" y1="2" x2="6" y2="4" />
                      <line x1="6" y1="8" x2="6" y2="10" />
                      <line x1="2" y1="6" x2="4" y2="6" />
                      <line x1="8" y1="6" x2="10" y2="6" />
                    </svg>
                  </span>
                  <span className="font-mono text-[11px]">{item.label}</span>
                </Command.Item>
              ))}
            </Command.Group>
          )}

          {/* Findings */}
          <Command.Group
            heading="Findings"
            className="px-2 pt-2 pb-1"
            style={{ '--cmdk-group-heading-color': 'var(--text-muted)' }}
          >
            {findingItems
              .filter((item) => !recentIds.has(item.id))
              .map((item) => (
                <Command.Item
                  key={item.id}
                  value={item.id}
                  keywords={item.keywords}
                  onSelect={() => handleFindingSelect(item.id)}
                  className="flex items-center gap-2 px-2 py-1.5 rounded text-xs cursor-pointer data-[selected=true]:bg-cyan-dim data-[selected=true]:text-cyan"
                  style={{ color: 'var(--text-primary)' }}
                >
                  <span className="font-mono text-[11px] w-16 shrink-0" style={{ color: 'var(--text-muted)' }}>
                    {item.id}
                  </span>
                  <span className="font-sans text-xs truncate">{item.label.replace(/^F-\d+\s+/, '')}</span>
                </Command.Item>
              ))}
          </Command.Group>

          {/* Actions */}
          <Command.Group
            heading="Actions"
            className="px-2 pt-2 pb-1"
            style={{ '--cmdk-group-heading-color': 'var(--text-muted)' }}
          >
            <Command.Item
              value="action-approve"
              onSelect={handleApproveCurrent}
              className="flex items-center gap-2 px-2 py-1.5 rounded text-xs cursor-pointer data-[selected=true]:bg-cyan-dim data-[selected=true]:text-cyan"
              style={{ color: 'var(--jade)' }}
            >
              <span className="font-mono text-[11px]">✓</span>
              <span>Approve current finding</span>
              {selectedFindingId && (
                <span className="ml-auto font-mono text-[10px] opacity-60">({selectedFindingId})</span>
              )}
            </Command.Item>
            <Command.Item
              value="action-reject"
              onSelect={handleRejectCurrent}
              className="flex items-center gap-2 px-2 py-1.5 rounded text-xs cursor-pointer data-[selected=true]:bg-cyan-dim data-[selected=true]:text-cyan"
              style={{ color: 'var(--crimson)' }}
            >
              <span className="font-mono text-[11px]">✗</span>
              <span>Reject current finding</span>
              {selectedFindingId && (
                <span className="ml-auto font-mono text-[10px] opacity-60">({selectedFindingId})</span>
              )}
            </Command.Item>
            <Command.Item
              value="action-commit"
              onSelect={handleOpenCommit}
              className="flex items-center gap-2 px-2 py-1.5 rounded text-xs cursor-pointer data-[selected=true]:bg-cyan-dim data-[selected=true]:text-cyan"
              style={{ color: 'var(--amber)' }}
            >
              <span className="font-mono text-[11px]">↑</span>
              <span>Open commit drawer</span>
            </Command.Item>
            <Command.Item
              value="action-refresh"
              onSelect={handleRefresh}
              className="flex items-center gap-2 px-2 py-1.5 rounded text-xs cursor-pointer data-[selected=true]:bg-cyan-dim data-[selected=true]:text-cyan"
              style={{ color: 'var(--text-primary)' }}
            >
              <span className="font-mono text-[11px]">↻</span>
              <span>Refresh data</span>
            </Command.Item>
            <Command.Item
              value="action-signout"
              onSelect={handleSignOut}
              className="flex items-center gap-2 px-2 py-1.5 rounded text-xs cursor-pointer data-[selected=true]:bg-cyan-dim data-[selected=true]:text-cyan"
              style={{ color: 'var(--text-muted)' }}
            >
              <span className="font-mono text-[11px]">⏻</span>
              <span>Sign out</span>
            </Command.Item>
          </Command.Group>
        </Command.List>

        {/* Footer hint */}
        <div
          className="flex items-center gap-3 px-3 py-1.5 border-t font-mono text-[10px]"
          style={{ borderColor: 'var(--border-faint)', color: 'var(--text-ghost)' }}
        >
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
        </div>
      </div>
    </Command.Dialog>
  )
}
