import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { CheckCheck, ListChecks } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { parseHashFilters } from '@/hooks/useHashRoute'
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
// Findings (handoff Screen 2) — full-height flex column: header + stat cards
// + two-pane grid (5fr list / 7fr detail). List uses a unified filter-dropdown
// (replaces the old tab-strip). Detail shows the three handoff fields only
// (Observation·fact · Interpretation·analysis · Justification & custody).
// Keyboard review (j/k/a/s/r) + step-up modal preserved. Store/api/hooks
// public paths unchanged.
// ─────────────────────────────────────────────────────────────────────────

function EmptyDetail() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 text-center text-muted-foreground">
      <ListChecks className="size-8 opacity-40" aria-hidden />
      <p className="mono text-sm">Select a finding to review</p>
    </div>
  )
}

/** Header "Commit to record" button — glass chip, orange text, staged-count badge. */
function CommitButton({ stagedCount, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-2 rounded-[9px] border px-3.5 py-1.5 text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      style={{
        background: 'linear-gradient(155deg,var(--bg-raised),var(--bg-surface))',
        borderColor: 'color-mix(in srgb,var(--orange) 38%,var(--border-hard))',
        color: 'var(--orange)',
        boxShadow: 'var(--edge)',
      }}
    >
      <CheckCheck className="size-4 shrink-0" aria-hidden />
      Commit to record
      <span
        className="mono rounded-md px-1.5 py-px text-[11px] font-semibold"
        style={{ background: 'color-mix(in srgb,var(--orange) 16%,transparent)' }}
      >
        {stagedCount}
      </span>
    </button>
  )
}

/** 4 symmetric stat cards — Findings / Approved / Pending / Staged. */
function StatCards({ counts }) {
  const cards = [
    { label: 'Findings', value: counts.total, color: 'var(--text-bright)', wash: 'transparent' },
    { label: 'Approved', value: counts.approved, color: 'var(--jade)', wash: 'color-mix(in srgb,var(--jade) 8%,transparent)' },
    { label: 'Pending',  value: counts.pending,  color: 'var(--amber)', wash: 'color-mix(in srgb,var(--amber) 8%,transparent)' },
    { label: 'Staged',   value: counts.staged,   color: 'var(--violet)', wash: 'color-mix(in srgb,var(--violet) 8%,transparent)' },
  ]
  return (
    <div className="grid shrink-0 gap-3" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
      {cards.map((c) => (
        <div
          key={c.label}
          className="rounded-[12px] border p-3"
          style={{
            background: c.wash,
            borderColor: 'var(--border-soft)',
            boxShadow: 'var(--edge)',
          }}
        >
          <div
            className="font-display text-[22px] font-bold leading-none"
            style={{ color: c.color }}
          >
            {c.value ?? 0}
          </div>
          <div
            className="mono mt-1.5 text-[9px] uppercase tracking-[.12em]"
            style={{ color: 'var(--text-muted)' }}
          >
            {c.label}
          </div>
        </div>
      ))}
    </div>
  )
}

export function FindingsTab() {
  const {
    findings, delta, setDelta, selectedFindingId, setSelectedFindingId, timeline,
    addToast, isLoading, findingsFilter, findingsHostFilter, findingsAccountFilter,
    setActiveTab, commandPaletteOpen, user, setCommitDrawerOpen,
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
    setCommitDrawerOpen: s.setCommitDrawerOpen,
  }))

  const canReview = (user?.role || '').toLowerCase() === 'examiner'
  const [search, setSearch] = useState('')
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState(() => new Set())
  const [stepUpOpen, setStepUpOpen] = useState(false)

  // Severity filter rides the hash (`#/findings?sev=high`) — kept in sync on
  // back/forward (RUN-4c deep-link plumbing).
  const [severityFilter, setSeverityFilter] = useState(() => parseHashFilters(window.location.hash).sev ?? null)
  useEffect(() => {
    const sync = () => setSeverityFilter(parseHashFilters(window.location.hash).sev ?? null)
    window.addEventListener('hashchange', sync)
    return () => window.removeEventListener('hashchange', sync)
  }, [])
  const clearSeverity = useCallback(() => {
    setSeverityFilter(null)
    window.history.replaceState(null, '', '#/findings')
  }, [])

  const findingById = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings])
  const deltaById = useMemo(() => new Map((delta ?? []).map((d) => [d.id, d])), [delta])
  const filtered = useMemo(
    () => filterFindings(findings, { filter: findingsFilter, host: findingsHostFilter, account: findingsAccountFilter, confidence: severityFilter, search }),
    [findings, findingsFilter, findingsHostFilter, findingsAccountFilter, severityFilter, search],
  )
  const counts = useMemo(() => {
    const base = reviewCounts(findings)
    const approved = findings.filter((f) => (f.status ?? '').toLowerCase() === 'approved').length
    const staged = (delta ?? []).filter((d) => d.action === 'stage').length
    return { ...base, total: findings.length, approved, staged }
  }, [findings, delta])

  const stagedCount = (delta ?? []).length

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
      if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault()
        const nextF = idx < 0 ? list[0] : list[idx + 1]
        if (nextF) setSelectedFindingId(nextF.id)
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault()
        if (idx > 0) setSelectedFindingId(list[idx - 1].id)
      } else if (canReview && e.key === 'a' && curId) {
        e.preventDefault()
        setStepUpOpen(true)
      } else if (canReview && e.key === 's' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'stage')
      } else if (canReview && e.key === 'r' && curId) {
        e.preventDefault()
        stageRef.current(curId, 'reject')
      } else if (e.key === 'Escape') {
        // Esc closes any open overlay — handled in child modals; nothing to do here
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [commandPaletteOpen, canReview, setSelectedFindingId])

  // Full-height flex column: header (shrink-0) + stat cards (shrink-0) + two-pane grid (flex-1)
  return (
    <div
      className="flex flex-col overflow-hidden"
      style={{ height: 'calc(100vh - 86px)' }}
    >
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="flex shrink-0 items-start justify-between gap-4 px-5 pt-5 pb-4">
        <div>
          <h1
            className="font-display font-bold leading-none"
            style={{ fontSize: '24px', letterSpacing: '-.4px', color: 'var(--text-bright)' }}
          >
            Findings review
          </h1>
          <p className="mono mt-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
            <kbd className="mono rounded border border-border bg-secondary px-1 py-px text-[10px]">j</kbd>
            <kbd className="mono ml-1 rounded border border-border bg-secondary px-1 py-px text-[10px]">k</kbd>
            {' '}move ·{' '}
            <kbd className="mono rounded border border-border bg-secondary px-1 py-px text-[10px]">a</kbd>
            {' '}approve ·{' '}
            <kbd className="mono rounded border border-border bg-secondary px-1 py-px text-[10px]">r</kbd>
            {' '}reject ·{' '}
            <kbd className="mono rounded border border-border bg-secondary px-1 py-px text-[10px]">s</kbd>
            {' '}stage
          </p>
        </div>
        <CommitButton stagedCount={stagedCount} onClick={() => setCommitDrawerOpen(true)} />
      </div>

      {/* ── Stat cards ──────────────────────────────────────────────── */}
      <div className="shrink-0 px-5 pb-4">
        <StatCards counts={counts} />
      </div>

      {/* ── Two-pane grid ────────────────────────────────────────────── */}
      <div
        className="min-h-0 flex-1 overflow-hidden"
        style={{ display: 'grid', gridTemplateColumns: 'minmax(0,5fr) minmax(0,7fr)' }}
      >
        <FindingsList
          list={filtered}
          loading={isLoading}
          counts={counts}
          canReview={canReview}
          search={search}
          onSearch={setSearch}
          severityFilter={severityFilter}
          onClearSeverity={clearSeverity}
          selectMode={selectMode}
          onToggleSelectMode={() => {
            setSelectMode((v) => !v)
            setSelectedIds(new Set())
          }}
          selectedIds={selectedIds}
          onToggleSelectId={toggleSelectId}
          onBatch={batch}
        />

        <div className="flex min-w-0 flex-col overflow-hidden">
          {currentFinding ? (
            <FindingDetail
              key={currentFinding.id}
              finding={currentFinding}
              stagedItem={stagedItem}
              timeline={timeline}
              canReview={canReview}
              addToast={addToast}
              stepUpOpen={stepUpOpen}
              onStepUpClose={() => setStepUpOpen(false)}
              onStepUpOpen={() => setStepUpOpen(true)}
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
    </div>
  )
}
