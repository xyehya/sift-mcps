import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ListChecks } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { postDelta, deleteDelta } from '@/api/endpoints'
import {
  buildEditItem,
  buildStageItem,
  filterFindings,
  reviewCounts,
  upsertDelta,
} from '@/components/findings/findings-utils'
import { FindingsList } from '@/components/findings/FindingsList'
import { FindingDetail } from '@/components/findings/FindingDetail'

// ─────────────────────────────────────────────────────────────────────────
// Findings (spec §4 / §8 parity) — list + filter + review (approve/reject/edit)
// + stage; commit happens in the shared CommitDrawer. Behaviour is ported from
// the old 1380-line monolith and decomposed into List + Detail + EditableField
// + Sidebar + AuditTrail (each ≤400 lines), preserving the /api/delta contract
// (POST replaces the whole delta document). RBAC: examiners review/stage/edit;
// readonly users get a read-only view with actions hidden + a reason.
// ─────────────────────────────────────────────────────────────────────────

function EmptyDetail() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 text-center text-muted-foreground">
      <ListChecks className="size-8 opacity-40" aria-hidden />
      <p className="mono text-sm">Select a finding to review</p>
    </div>
  )
}

export function FindingsTab() {
  const {
    findings, delta, setDelta, selectedFindingId, setSelectedFindingId, timeline,
    addToast, isLoading, findingsFilter, findingsHostFilter, findingsAccountFilter,
    setActiveTab, commandPaletteOpen, user,
  } = useStoreSlice((s) => ({
    findings: s.findings,
    delta: s.delta,
    setDelta: s.setDelta,
    selectedFindingId: s.selectedFindingId,
    setSelectedFindingId: s.setSelectedFindingId,
    timeline: s.timeline,
    addToast: s.addToast,
    isLoading: s.isLoading,
    findingsFilter: s.findingsFilter,
    findingsHostFilter: s.findingsHostFilter,
    findingsAccountFilter: s.findingsAccountFilter,
    setActiveTab: s.setActiveTab,
    commandPaletteOpen: s.commandPaletteOpen,
    user: s.user,
  }))

  const canReview = (user?.role || '').toLowerCase() === 'examiner'
  const [search, setSearch] = useState('')
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState(() => new Set())

  const findingById = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings])
  const deltaById = useMemo(() => new Map((delta ?? []).map((d) => [d.id, d])), [delta])
  const filtered = useMemo(
    () => filterFindings(findings, { filter: findingsFilter, host: findingsHostFilter, account: findingsAccountFilter, search }),
    [findings, findingsFilter, findingsHostFilter, findingsAccountFilter, search],
  )
  const counts = useMemo(() => reviewCounts(findings), [findings])

  const currentFinding = selectedFindingId ? findingById.get(selectedFindingId) ?? null : null
  const stagedItem = currentFinding ? deltaById.get(currentFinding.id) ?? null : null

  // ---- delta mutations (POST replaces the whole delta document) ----
  const stage = useCallback(
    async (findingId, action) => {
      const f = findingById.get(findingId)
      if (!f) return
      const next = upsertDelta(delta, buildStageItem(f, action))
      const VERB = { approve: 'Approved', reject: 'Rejected', stage: 'Staged' }
      const TONE = { approve: 'success', reject: 'warn', stage: 'info' }
      try {
        await postDelta({ items: next })
        setDelta(next)
        addToast(`${VERB[action] ?? 'Staged'} ${findingId} — staged for commit`, TONE[action] ?? 'info')
      } catch (ex) {
        addToast(ex.message, 'error')
      }
    },
    [findingById, delta, setDelta, addToast],
  )

  const unstage = useCallback(
    async (findingId) => {
      try {
        await deleteDelta(findingId)
        setDelta(delta.filter((d) => d.id !== findingId))
        addToast(`Unstaged ${findingId}`, 'info')
      } catch (ex) {
        addToast(ex.message, 'error')
      }
    },
    [delta, setDelta, addToast],
  )

  const editField = useCallback(
    async (finding, field, original, modified) => {
      const next = upsertDelta(delta, buildEditItem(deltaById.get(finding.id), finding, field, original, modified))
      try {
        await postDelta({ items: next })
        setDelta(next)
        addToast(`Updated ${field} (staged)`, 'success')
      } catch (ex) {
        addToast(ex.message, 'error')
      }
    },
    [delta, deltaById, setDelta, addToast],
  )

  async function batch(action) {
    for (const id of selectedIds) await stage(id, action)
    setSelectedIds(new Set())
    setSelectMode(false)
  }

  function toggleSelectId(id) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // ---- keyboard review (j/k navigate · a approve · s stage · r reject) ----
  const filteredRef = useRef(filtered)
  const selectedRef = useRef(selectedFindingId)
  const stageRef = useRef(stage)
  useEffect(() => { filteredRef.current = filtered }, [filtered])
  useEffect(() => { selectedRef.current = selectedFindingId }, [selectedFindingId])
  useEffect(() => { stageRef.current = stage }, [stage])

  useEffect(() => {
    function onKey(e) {
      const tag = document.activeElement?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || document.activeElement?.isContentEditable) return
      if (commandPaletteOpen) return
      const list = filteredRef.current
      const curId = selectedRef.current
      const idx = list.findIndex((f) => f.id === curId)
      if (e.key === 'j') {
        e.preventDefault()
        const nextF = idx < 0 ? list[0] : list[idx + 1]
        if (nextF) setSelectedFindingId(nextF.id)
      } else if (e.key === 'k') {
        e.preventDefault()
        if (idx > 0) setSelectedFindingId(list[idx - 1].id)
      } else if (canReview && e.key === 'a' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'approve')
      } else if (canReview && e.key === 's' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'stage')
      } else if (canReview && e.key === 'r' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'reject')
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [commandPaletteOpen, canReview, setSelectedFindingId])

  return (
    <div className="flex h-full overflow-hidden bg-background">
      <FindingsList
        list={filtered}
        loading={isLoading}
        counts={counts}
        canReview={canReview}
        search={search}
        onSearch={setSearch}
        selectMode={selectMode}
        onToggleSelectMode={() => {
          setSelectMode((v) => !v)
          setSelectedIds(new Set())
        }}
        selectedIds={selectedIds}
        onToggleSelectId={toggleSelectId}
        onBatch={batch}
      />

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {currentFinding ? (
          <FindingDetail
            key={currentFinding.id}
            finding={currentFinding}
            stagedItem={stagedItem}
            timeline={timeline}
            canReview={canReview}
            onApprove={() => stage(currentFinding.id, 'approve')}
            onStage={() => stage(currentFinding.id, 'stage')}
            onReject={() => stage(currentFinding.id, 'reject')}
            onUnstage={stagedItem ? () => unstage(currentFinding.id) : null}
            onEdit={(field, original, modified) => editField(currentFinding, field, original, modified)}
            onNavigate={(fid) => {
              setSelectedFindingId(fid)
              setActiveTab('findings')
            }}
          />
        ) : (
          <EmptyDetail />
        )}
      </div>
    </div>
  )
}
