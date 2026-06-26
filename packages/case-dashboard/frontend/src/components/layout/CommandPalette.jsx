import { useMemo, useState } from 'react'
import { ArrowUpCircle, Check, FileSearch, RefreshCw, X } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { useAuth } from '@/lib/auth-context'
import { navigateToTab } from '@/hooks/useHashRoute'
import { useDeltaRefetch } from '@/hooks/useDeltaRefetch'
import { postDelta } from '@/api/endpoints'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from '@/components/ui/command'

// ─────────────────────────────────────────────────────────────────────────
// Command palette (⌘K) — ported from the old CommandPalette: jump to a
// finding, stage approve/reject for the selected finding (staging only — the
// commit still requires the password challenge in the Commit Drawer), open the
// commit drawer, refresh, and sign out. Recent selections float to the top.
// ─────────────────────────────────────────────────────────────────────────

const MAX_RECENT = 5

export function CommandPalette() {
  const { logout } = useAuth()
  const {
    open,
    setOpen,
    findings,
    selectedFindingId,
    setSelectedFindingId,
    setActiveTab,
    delta,
    setDelta,
    setCommitDrawerOpen,
    addToast,
  } = useStoreSlice((s) => ({
    open: s.commandPaletteOpen,
    setOpen: s.setCommandPaletteOpen,
    findings: s.findings,
    selectedFindingId: s.selectedFindingId,
    setSelectedFindingId: s.setSelectedFindingId,
    setActiveTab: s.setActiveTab,
    delta: s.delta,
    setDelta: s.setDelta,
    setCommitDrawerOpen: s.setCommitDrawerOpen,
    addToast: s.addToast,
  }))

  const refetchDelta = useDeltaRefetch()
  const [recentIds, setRecentIds] = useState([])
  const findingById = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings])

  function close() {
    setOpen(false)
  }

  function pushRecent(id) {
    setRecentIds((prev) => [id, ...prev.filter((r) => r !== id)].slice(0, MAX_RECENT))
  }

  function selectFinding(id) {
    if (!findingById.has(id)) return
    pushRecent(id)
    setSelectedFindingId(id)
    navigateToTab(setActiveTab, 'findings')
    close()
  }

  // Stage approve/reject — identical delta shape to FindingsTab.stageAction.
  async function stage(action) {
    const finding = findingById.get(selectedFindingId)
    if (!finding) {
      addToast('No finding selected — open Findings first', 'info')
      close()
      return
    }
    const newItem = {
      id: finding.id,
      type: finding.type ?? 'finding',
      action,
      content_hash_at_review: finding.content_hash ?? '',
      modifications: {},
    }
    const newDelta = [...delta.filter((d) => d.id !== finding.id), newItem]
    try {
      await postDelta({ items: newDelta })
      setDelta(newDelta)
      addToast(`${action === 'approve' ? 'Approved' : 'Rejected'} ${finding.id} — staged`, action === 'approve' ? 'success' : 'warn')
      refetchDelta() // B2: reconcile badge with server truth without waiting for the 15s poll
    } catch (ex) {
      addToast(ex.message, 'error')
    }
    close()
  }

  const recentFindings = useMemo(
    () => recentIds.map((id) => findingById.get(id)).filter(Boolean),
    [recentIds, findingById],
  )
  const recentSet = useMemo(() => new Set(recentIds), [recentIds])

  return (
    <CommandDialog open={open} onOpenChange={setOpen} className="max-w-xl">
      <CommandInput placeholder="Search findings or run a command…" />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>

        {recentFindings.length > 0 && (
          <CommandGroup heading="Recently selected">
            {recentFindings.map((f) => (
              <CommandItem key={`recent-${f.id}`} value={`recent-${f.id}`} onSelect={() => selectFinding(f.id)}>
                <FileSearch className="opacity-60" />
                <span className="mono text-xs">{f.id}</span>
                <span className="truncate text-muted-foreground">{(f.title ?? '').slice(0, 56)}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}

        <CommandGroup heading="Findings">
          {findings
            .filter((f) => !recentSet.has(f.id))
            .map((f) => (
              <CommandItem
                key={f.id}
                value={`${f.id} ${f.title ?? ''}`}
                onSelect={() => selectFinding(f.id)}
              >
                <span className="mono w-16 shrink-0 text-xs text-muted-foreground">{f.id}</span>
                <span className="truncate">{(f.title ?? '').slice(0, 56)}</span>
              </CommandItem>
            ))}
        </CommandGroup>

        <CommandGroup heading="Actions">
          <CommandItem value="approve current finding" onSelect={() => stage('approve')}>
            <Check className="text-status-approved" />
            Approve current finding
            {selectedFindingId && <CommandShortcut className="mono">{selectedFindingId}</CommandShortcut>}
          </CommandItem>
          <CommandItem value="reject current finding" onSelect={() => stage('reject')}>
            <X className="text-destructive" />
            Reject current finding
            {selectedFindingId && <CommandShortcut className="mono">{selectedFindingId}</CommandShortcut>}
          </CommandItem>
          <CommandItem
            value="open commit drawer"
            onSelect={() => {
              setCommitDrawerOpen(true)
              close()
            }}
          >
            <ArrowUpCircle className="text-status-pending" />
            Open commit drawer
          </CommandItem>
          <CommandItem value="refresh data" onSelect={() => window.location.reload()}>
            <RefreshCw />
            Refresh data
          </CommandItem>
          <CommandItem
            value="sign out"
            onSelect={() => {
              close()
              logout()
            }}
          >
            <X />
            Sign out
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  )
}
